"""
Benchmark tool for comparing wipe performance.
"""

import os
import time
import tempfile
import argparse
import statistics
from typing import List, Dict, Tuple, Any

# Import both implementations
from .core.wipe_engine import WipeEngine, SanitizationMethod
from .core.fast_wipe import FastWipeEngine, WipeProgress

class BenchmarkResult:
    """Stores benchmark results for a single test."""
    
    def __init__(self, name: str):
        self.name = name
        self.times: List[float] = []
        self.speeds: List[float] = []  # in MB/s
    
    def add_run(self, time_taken: float, size_mb: float):
        """Add a benchmark run result."""
        self.times.append(time_taken)
        self.speeds.append(size_mb / time_taken if time_taken > 0 else 0)
    
    @property
    def avg_time(self) -> float:
        """Average time in seconds."""
        return statistics.mean(self.times) if self.times else 0
    
    @property
    def avg_speed(self) -> float:
        """Average speed in MB/s."""
        return statistics.mean(self.speeds) if self.speeds else 0
    
    @property
    def min_speed(self) -> float:
        """Minimum speed in MB/s."""
        return min(self.speeds) if self.speeds else 0
    
    @property
    def max_speed(self) -> float:
        """Maximum speed in MB/s."""
        return max(self.speeds) if self.speeds else 0
    
    @property
    def std_dev(self) -> float:
        """Standard deviation of speeds."""
        return statistics.stdev(self.speeds) if len(self.speeds) > 1 else 0

class DiskWipeBenchmark:
    """Benchmark different disk wiping implementations."""
    
    def __init__(self, test_size_mb: int = 100, runs: int = 3):
        """
        Initialize the benchmark.
        
        Args:
            test_size_mb: Size of test data in MB
            runs: Number of runs per test
        """
        self.test_size_mb = test_size_mb
        self.test_size_bytes = test_size_mb * 1024 * 1024
        self.runs = runs
        self.results: Dict[str, BenchmarkResult] = {}
    
    def _create_test_file(self) -> str:
        """Create a test file with random data."""
        fd, path = tempfile.mkstemp()
        try:
            with os.fdopen(fd, 'wb') as f:
                # Write random data to the file
                chunk_size = 1024 * 1024  # 1MB chunks
                remaining = self.test_size_bytes
                
                while remaining > 0:
                    chunk = os.urandom(min(chunk_size, remaining))
                    f.write(chunk)
                    remaining -= len(chunk)
                    
            return path
        except Exception as e:
            if os.path.exists(path):
                os.unlink(path)
            raise RuntimeError(f"Failed to create test file: {e}")
    
    def _run_legacy_wipe(self, test_file: str) -> float:
        """Run the legacy wipe implementation."""
        engine = WipeEngine()
        start_time = time.time()
        
        # Use a dummy progress callback
        def progress_callback(progress):
            pass
            
        engine.set_progress_callback(progress_callback)
        
        # Run the wipe
        result = engine.sanitize_device(
            test_file,
            method=SanitizationMethod.OVERWRITE_SINGLE,
            verify=False
        )
        
        if result.result != SanitizationResult.SUCCESS:
            raise RuntimeError(f"Legacy wipe failed: {result.error_message}")
            
        return time.time() - start_time
    
    def _run_fast_wipe(self, test_file: str) -> float:
        """Run the optimized fast wipe implementation."""
        engine = FastWipeEngine()
        start_time = time.time()
        
        # Use a dummy progress callback
        def progress_callback(progress):
            pass
            
        # Run the wipe
        progress = engine.wipe_device(test_file, "random", verify=False)
        
        if not progress.is_complete:
            raise RuntimeError(f"Fast wipe failed: {progress.error}")
            
        return time.time() - start_time
    
    def run_benchmark(self):
        """Run all benchmarks."""
        print(f"Running benchmarks with {self.test_size_mb}MB test data ({self.runs} runs per test)\n")
        
        # Test legacy implementation
        self._run_test("Legacy Wipe", self._run_legacy_wipe)
        
        # Test fast implementation
        self._run_test("Fast Wipe", self._run_fast_wipe)
        
        # Print results
        self._print_results()
    
    def _run_test(self, name: str, test_func: callable):
        """Run a single benchmark test."""
        print(f"Running {name} benchmark...")
        result = BenchmarkResult(name)
        
        for i in range(self.runs):
            test_file = self._create_test_file()
            try:
                print(f"  Run {i+1}/{self.runs}: ", end='', flush=True)
                
                start_time = time.time()
                time_taken = test_func(test_file)
                
                # Calculate metrics
                speed = self.test_size_mb / time_taken
                
                print(f"{time_taken:.2f}s ({speed:.2f} MB/s)")
                result.add_run(time_taken, self.test_size_mb)
                
            except Exception as e:
                print(f"Error: {e}")
                if os.path.exists(test_file):
                    os.unlink(test_file)
                raise
            finally:
                if os.path.exists(test_file):
                    os.unlink(test_file)
        
        self.results[name] = result
    
    def _print_results(self):
        """Print benchmark results."""
        print("\n" + "=" * 80)
        print("BENCHMARK RESULTS")
        print("=" * 80)
        
        # Find the longest name for formatting
        max_name_len = max(len(name) for name in self.results)
        
        # Print header
        print(f"{'Method':<{max_name_len}} | {'Avg Speed (MB/s)':>15} | {'Min':>10} | {'Max':>10} | {'Std Dev':>10} | {'Runs'}")
        print("-" * (max_name_len + 60))
        
        # Print results for each test
        for name, result in self.results.items():
            print(f"{name:<{max_name_len}} | "
                  f"{result.avg_speed:>15.2f} | "
                  f"{result.min_speed:>10.2f} | "
                  f"{result.max_speed:>10.2f} | "
                  f"{result.std_dev:>10.2f} | "
                  f"{len(result.times)}")
        
        # Calculate improvement
        if len(self.results) >= 2:
            legacy = self.results["Legacy Wipe"].avg_speed
            fast = self.results["Fast Wipe"].avg_speed
            if legacy > 0:
                improvement = ((fast - legacy) / legacy) * 100
                print(f"\nPerformance improvement: {improvement:.1f}% faster")
        
        print("=" * 80)

def main():
    """Main entry point for the benchmark tool."""
    parser = argparse.ArgumentParser(description="Disk Wipe Performance Benchmark")
    parser.add_argument("-s", "--size", type=int, default=100,
                       help="Test size in MB (default: 100)")
    parser.add_argument("-r", "--runs", type=int, default=3,
                       help="Number of runs per test (default: 3)")
    
    args = parser.parse_args()
    
    try:
        benchmark = DiskWipeBenchmark(
            test_size_mb=args.size,
            runs=args.runs
        )
        benchmark.run_benchmark()
    except KeyboardInterrupt:
        print("\nBenchmark cancelled by user")
        return 1
    except Exception as e:
        print(f"Error: {e}")
        return 1
    
    return 0

if __name__ == "__main__":
    import sys
    sys.exit(main())
