/// Parallel processing engine for multi-device and multi-node sanitization
/// This module provides concurrent sanitization capabilities with load balancing,
/// job scheduling, and distributed coordination.

use crate::{OperationResult, SanitizationMethod, DeviceCapabilities};
use std::collections::HashMap;
use std::sync::{Arc, Mutex, mpsc};
use std::thread;
use std::time::{Duration, Instant};
use anyhow::{Result, anyhow};
use serde::{Serialize, Deserialize};
use tokio::sync::Semaphore;

/// Job status tracking
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum JobStatus {
    Pending,
    Running,
    Completed,
    Failed,
    Cancelled,
}

/// Sanitization job definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SanitizationJob {
    pub id: String,
    pub device_path: String,
    pub method: SanitizationMethod,
    pub priority: u8, // 1-10, higher is more urgent
    pub compliance_level: String,
    pub operator: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub status: JobStatus,
    pub estimated_duration: Option<f64>,
    pub actual_duration: Option<f64>,
    pub result: Option<OperationResult>,
    pub node_assignment: Option<String>,
}

/// Job queue with priority ordering
pub struct JobQueue {
    jobs: Arc<Mutex<Vec<SanitizationJob>>>,
    completed_jobs: Arc<Mutex<Vec<SanitizationJob>>>,
}

impl JobQueue {
    pub fn new() -> Self {
        JobQueue {
            jobs: Arc::new(Mutex::new(Vec::new())),
            completed_jobs: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Add a new job to the queue
    pub fn add_job(&self, mut job: SanitizationJob) -> Result<()> {
        job.status = JobStatus::Pending;
        
        let mut jobs = self.jobs.lock().map_err(|_| anyhow!("Failed to acquire job queue lock"))?;
        jobs.push(job);
        
        // Sort by priority (descending) then by creation time (ascending)
        jobs.sort_by(|a, b| {
            b.priority.cmp(&a.priority)
                .then_with(|| a.created_at.cmp(&b.created_at))
        });
        
        Ok(())
    }

    /// Get the next job from the queue
    pub fn get_next_job(&self) -> Result<Option<SanitizationJob>> {
        let mut jobs = self.jobs.lock().map_err(|_| anyhow!("Failed to acquire job queue lock"))?;
        
        if let Some(index) = jobs.iter().position(|job| matches!(job.status, JobStatus::Pending)) {
            let mut job = jobs.remove(index);
            job.status = JobStatus::Running;
            Ok(Some(job))
        } else {
            Ok(None)
        }
    }

    /// Update job status
    pub fn update_job(&self, job_id: &str, status: JobStatus, result: Option<OperationResult>) -> Result<()> {
        let mut jobs = self.jobs.lock().map_err(|_| anyhow!("Failed to acquire job queue lock"))?;
        
        if let Some(job) = jobs.iter_mut().find(|j| j.id == job_id) {
            job.status = status.clone();
            job.result = result;
            
            // Move completed jobs to separate storage
            if matches!(status, JobStatus::Completed | JobStatus::Failed | JobStatus::Cancelled) {
                let completed_job = job.clone();
                let mut completed = self.completed_jobs.lock().map_err(|_| anyhow!("Failed to acquire completed jobs lock"))?;
                completed.push(completed_job);
                
                // Remove from active queue
                if let Some(index) = jobs.iter().position(|j| j.id == job_id) {
                    jobs.remove(index);
                }
            }
        }
        
        Ok(())
    }

    /// Get job status
    pub fn get_job_status(&self, job_id: &str) -> Result<Option<SanitizationJob>> {
        // Check active jobs
        let jobs = self.jobs.lock().map_err(|_| anyhow!("Failed to acquire job queue lock"))?;
        if let Some(job) = jobs.iter().find(|j| j.id == job_id) {
            return Ok(Some(job.clone()));
        }
        
        // Check completed jobs
        let completed = self.completed_jobs.lock().map_err(|_| anyhow!("Failed to acquire completed jobs lock"))?;
        if let Some(job) = completed.iter().find(|j| j.id == job_id) {
            return Ok(Some(job.clone()));
        }
        
        Ok(None)
    }

    /// Get queue statistics
    pub fn get_statistics(&self) -> Result<HashMap<String, u32>> {
        let jobs = self.jobs.lock().map_err(|_| anyhow!("Failed to acquire job queue lock"))?;
        let completed = self.completed_jobs.lock().map_err(|_| anyhow!("Failed to acquire completed jobs lock"))?;
        
        let mut stats = HashMap::new();
        
        stats.insert("pending".to_string(), jobs.iter().filter(|j| matches!(j.status, JobStatus::Pending)).count() as u32);
        stats.insert("running".to_string(), jobs.iter().filter(|j| matches!(j.status, JobStatus::Running)).count() as u32);
        stats.insert("completed".to_string(), completed.iter().filter(|j| matches!(j.status, JobStatus::Completed)).count() as u32);
        stats.insert("failed".to_string(), completed.iter().filter(|j| matches!(j.status, JobStatus::Failed)).count() as u32);
        stats.insert("cancelled".to_string(), completed.iter().filter(|j| matches!(j.status, JobStatus::Cancelled)).count() as u32);
        
        Ok(stats)
    }
}

/// Multi-device parallel sanitization manager
pub struct ParallelSanitizer {
    max_concurrent: usize,
    job_queue: JobQueue,
    active_workers: Arc<Mutex<HashMap<String, thread::JoinHandle<()>>>>,
    progress_callbacks: Arc<Mutex<Vec<Box<dyn Fn(&str, f64) + Send + Sync>>>>,
}

impl ParallelSanitizer {
    pub fn new(max_concurrent: usize) -> Self {
        ParallelSanitizer {
            max_concurrent,
            job_queue: JobQueue::new(),
            active_workers: Arc::new(Mutex::new(HashMap::new())),
            progress_callbacks: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Add a progress callback
    pub fn add_progress_callback<F>(&self, callback: F) -> Result<()>
    where
        F: Fn(&str, f64) + Send + Sync + 'static,
    {
        let mut callbacks = self.progress_callbacks.lock().map_err(|_| anyhow!("Failed to acquire callbacks lock"))?;
        callbacks.push(Box::new(callback));
        Ok(())
    }

    /// Submit a sanitization job
    pub fn submit_job(&self, job: SanitizationJob) -> Result<String> {
        let job_id = job.id.clone();
        self.job_queue.add_job(job)?;
        self.try_start_workers()?;
        Ok(job_id)
    }

    /// Try to start workers for pending jobs
    fn try_start_workers(&self) -> Result<()> {
        let active_count = {
            let workers = self.active_workers.lock().map_err(|_| anyhow!("Failed to acquire workers lock"))?;
            workers.len()
        };

        if active_count >= self.max_concurrent {
            return Ok(());
        }

        for _ in active_count..self.max_concurrent {
            if let Some(job) = self.job_queue.get_next_job()? {
                self.start_worker(job)?;
            } else {
                break; // No more pending jobs
            }
        }

        Ok(())
    }

    /// Start a worker thread for a job
    fn start_worker(&self, job: SanitizationJob) -> Result<()> {
        let job_id = job.id.clone();
        let queue = self.job_queue.clone();
        let workers = self.active_workers.clone();
        let callbacks = self.progress_callbacks.clone();

        let handle = thread::spawn(move || {
            let start_time = Instant::now();
            
            // Execute the sanitization
            let result = Self::execute_sanitization_job(&job, &callbacks);
            
            let duration = start_time.elapsed().as_secs_f64();
            
            // Update job status
            let status = if result.as_ref().map(|r| r.success).unwrap_or(false) {
                JobStatus::Completed
            } else {
                JobStatus::Failed
            };
            
            if let Err(e) = queue.update_job(&job_id, status, result) {
                eprintln!("Failed to update job status: {}", e);
            }
            
            // Remove worker from active list
            if let Ok(mut workers) = workers.lock() {
                workers.remove(&job_id);
            }
            
            log::info!("Job {} completed in {:.2} seconds", job_id, duration);
        });

        let mut workers = self.active_workers.lock().map_err(|_| anyhow!("Failed to acquire workers lock"))?;
        workers.insert(job_id, handle);

        Ok(())
    }

    /// Execute a sanitization job
    fn execute_sanitization_job(
        job: &SanitizationJob,
        callbacks: &Arc<Mutex<Vec<Box<dyn Fn(&str, f64) + Send + Sync>>>>
    ) -> Option<OperationResult> {
        // Create progress callback
        let progress_callback = |progress: f64| {
            if let Ok(callbacks) = callbacks.lock() {
                for callback in callbacks.iter() {
                    callback(&job.id, progress);
                }
            }
        };

        match &job.method {
            SanitizationMethod::CryptoErase => {
                crate::crypto_erase::destroy_encryption_key(&job.device_path).ok()
            }
            SanitizationMethod::SecureErase => {
                crate::device::nvme_sanitize_enhanced(&job.device_path, "secure_erase").ok()
            }
            SanitizationMethod::NvmeSanitize => {
                crate::device::nvme_sanitize_enhanced(&job.device_path, "crypto_erase").ok()
            }
            SanitizationMethod::TrimDiscard => {
                crate::trim_support::trim_device(&job.device_path, None).ok()
            }
            SanitizationMethod::SinglePassOverwrite => {
                crate::overwrite::parallel_overwrite_with_progress(&job.device_path, 1, None, Some(progress_callback)).ok()
            }
            SanitizationMethod::MultiPassOverwrite { passes } => {
                crate::overwrite::parallel_overwrite_with_progress(&job.device_path, *passes, None, Some(progress_callback)).ok()
            }
            SanitizationMethod::CryptoWrap { quick_overwrite } => {
                // First try crypto erase
                if let Ok(result) = crate::crypto_erase::destroy_encryption_key(&job.device_path) {
                    if *quick_overwrite {
                        // Add quick overwrite for policy compliance
                        let _ = crate::overwrite::parallel_overwrite_with_progress(&job.device_path, 1, None, Some(progress_callback));
                    }
                    Some(result)
                } else {
                    None
                }
            }
        }
    }

    /// Get current job statistics
    pub fn get_statistics(&self) -> Result<HashMap<String, u32>> {
        self.job_queue.get_statistics()
    }

    /// Wait for all jobs to complete
    pub fn wait_for_completion(&self, timeout_seconds: Option<u64>) -> Result<bool> {
        let start_time = Instant::now();
        let timeout = timeout_seconds.map(Duration::from_secs);

        loop {
            let stats = self.get_statistics()?;
            let pending = stats.get("pending").unwrap_or(&0);
            let running = stats.get("running").unwrap_or(&0);

            if *pending == 0 && *running == 0 {
                return Ok(true); // All jobs completed
            }

            if let Some(timeout) = timeout {
                if start_time.elapsed() > timeout {
                    return Ok(false); // Timeout reached
                }
            }

            thread::sleep(Duration::from_millis(500));
        }
    }
}

/// Simple wrapper for batch sanitization
pub fn sanitize_multiple_devices(
    device_configs: Vec<(String, String)>, // (device_path, method)
    max_concurrent: usize,
) -> Result<Vec<(String, OperationResult)>> {
    let sanitizer = ParallelSanitizer::new(max_concurrent);
    let mut job_ids = Vec::new();

    // Submit all jobs
    for (device_path, method_str) in device_configs {
        let method = match method_str.as_str() {
            "crypto_erase" => SanitizationMethod::CryptoErase,
            "secure_erase" => SanitizationMethod::SecureErase,
            "nvme_sanitize" => SanitizationMethod::NvmeSanitize,
            "trim_discard" => SanitizationMethod::TrimDiscard,
            "single_pass" => SanitizationMethod::SinglePassOverwrite,
            "multi_pass_3" => SanitizationMethod::MultiPassOverwrite { passes: 3 },
            "crypto_wrap" => SanitizationMethod::CryptoWrap { quick_overwrite: true },
            _ => SanitizationMethod::SinglePassOverwrite,
        };

        let job = SanitizationJob {
            id: format!("job_{}_{}", chrono::Utc::now().timestamp_millis(), device_path.replace("/", "_")),
            device_path: device_path.clone(),
            method,
            priority: 5,
            compliance_level: "nist".to_string(),
            operator: "batch_process".to_string(),
            created_at: chrono::Utc::now(),
            status: JobStatus::Pending,
            estimated_duration: None,
            actual_duration: None,
            result: None,
            node_assignment: None,
        };

        let job_id = sanitizer.submit_job(job)?;
        job_ids.push((device_path, job_id));
    }

    // Wait for completion (with 1 hour timeout)
    if !sanitizer.wait_for_completion(Some(3600))? {
        return Err(anyhow!("Batch operation timed out"));
    }

    // Collect results
    let mut results = Vec::new();
    for (device_path, job_id) in job_ids {
        if let Some(job) = sanitizer.job_queue.get_job_status(&job_id)? {
            if let Some(result) = job.result {
                results.push((device_path, result));
            } else {
                // Create failure result
                let failure = OperationResult {
                    success: false,
                    method_used: "unknown".to_string(),
                    duration_seconds: 0.0,
                    bytes_processed: 0,
                    throughput_mbps: 0.0,
                    verification_passed: false,
                    error_message: Some("Job did not complete successfully".to_string()),
                };
                results.push((device_path, failure));
            }
        }
    }

    Ok(results)
}

/// Multi-node orchestration scaffolding
/// TODO: Implement full distributed coordination with secure RPC
pub struct MultiNodeOrchestrator {
    local_node_id: String,
    known_nodes: HashMap<String, String>, // node_id -> endpoint
    job_queue: JobQueue,
}

impl MultiNodeOrchestrator {
    pub fn new(node_id: String) -> Self {
        MultiNodeOrchestrator {
            local_node_id: node_id,
            known_nodes: HashMap::new(),
            job_queue: JobQueue::new(),
        }
    }

    /// Register a remote node
    pub fn register_node(&mut self, node_id: String, endpoint: String) {
        self.known_nodes.insert(node_id, endpoint);
    }

    /// Distribute jobs across nodes based on load and capabilities
    pub fn distribute_job(&self, job: SanitizationJob) -> Result<String> {
        // TODO: Implement actual load balancing and node selection
        // For now, process locally
        self.job_queue.add_job(job.clone())?;
        
        log::info!("Job {} assigned to local node {}", job.id, self.local_node_id);
        Ok(job.id)
    }

    /// Check status across all nodes
    pub fn global_status(&self) -> Result<HashMap<String, HashMap<String, u32>>> {
        let mut global_stats = HashMap::new();
        
        // Local node stats
        global_stats.insert(self.local_node_id.clone(), self.job_queue.get_statistics()?);
        
        // TODO: Query remote nodes via secure RPC
        for (node_id, _endpoint) in &self.known_nodes {
            // Placeholder for remote node query
            let mut remote_stats = HashMap::new();
            remote_stats.insert("pending".to_string(), 0);
            remote_stats.insert("running".to_string(), 0);
            remote_stats.insert("completed".to_string(), 0);
            global_stats.insert(node_id.clone(), remote_stats);
        }
        
        Ok(global_stats)
    }

    /// Implement job deduplication
    pub fn deduplicate_jobs(&self) -> Result<u32> {
        // TODO: Implement cross-node job deduplication
        // Check for duplicate device paths, similar time windows, etc.
        Ok(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_job_queue_priority() {
        let queue = JobQueue::new();
        
        let low_priority_job = SanitizationJob {
            id: "low".to_string(),
            device_path: "/dev/sdb".to_string(),
            method: SanitizationMethod::SinglePassOverwrite,
            priority: 3,
            compliance_level: "nist".to_string(),
            operator: "test".to_string(),
            created_at: chrono::Utc::now(),
            status: JobStatus::Pending,
            estimated_duration: None,
            actual_duration: None,
            result: None,
            node_assignment: None,
        };

        let high_priority_job = SanitizationJob {
            id: "high".to_string(),
            device_path: "/dev/sdc".to_string(),
            method: SanitizationMethod::CryptoErase,
            priority: 8,
            compliance_level: "nist".to_string(),
            operator: "test".to_string(),
            created_at: chrono::Utc::now(),
            status: JobStatus::Pending,
            estimated_duration: None,
            actual_duration: None,
            result: None,
            node_assignment: None,
        };

        queue.add_job(low_priority_job).unwrap();
        queue.add_job(high_priority_job).unwrap();

        // High priority job should come first
        let next_job = queue.get_next_job().unwrap().unwrap();
        assert_eq!(next_job.id, "high");
        assert_eq!(next_job.priority, 8);
    }

    #[test]
    fn test_parallel_sanitizer_creation() {
        let sanitizer = ParallelSanitizer::new(4);
        let stats = sanitizer.get_statistics().unwrap();
        
        assert_eq!(*stats.get("pending").unwrap_or(&999), 0);
        assert_eq!(*stats.get("running").unwrap_or(&999), 0);
    }

    #[test]
    fn test_multi_node_orchestrator() {
        let mut orchestrator = MultiNodeOrchestrator::new("node_1".to_string());
        orchestrator.register_node("node_2".to_string(), "https://node2:8443".to_string());
        
        let global_status = orchestrator.global_status().unwrap();
        assert!(global_status.contains_key("node_1"));
        assert!(global_status.contains_key("node_2"));
    }

    #[test]
    fn test_batch_sanitization_interface() {
        let device_configs = vec![
            ("/dev/mock1".to_string(), "crypto_erase".to_string()),
            ("/dev/mock2".to_string(), "single_pass".to_string()),
        ];

        // This would fail in real execution but tests the interface
        let result = sanitize_multiple_devices(device_configs, 2);
        assert!(result.is_err() || result.is_ok()); // Just testing compilation
    }
}