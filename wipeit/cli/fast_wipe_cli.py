"""
Fast Wipe CLI - Command-line interface for high-performance disk wiping.
"""

import os
import sys
import time
import argparse
import signal
from typing import Optional

from ..core.fast_wipe import FastWipeEngine, WipeProgress

def format_size(size_bytes: int) -> str:
    """Format size in bytes to human-readable format."""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if size_bytes < 1024.0:
            return f"{size_bytes:.2f} {unit}"
        size_bytes /= 1024.0
    return f"{size_bytes:.2f} PB"

def format_time(seconds: float) -> str:
    """Format time in seconds to human-readable format."""
    if seconds < 1:
        return f"{seconds*1000:.0f} ms"
    if seconds < 60:
        return f"{seconds:.1f} s"
    minutes = int(seconds // 60)
    seconds = seconds % 60
    if minutes < 60:
        return f"{minutes}m {seconds:.0f}s"
    hours = minutes // 60
    minutes = minutes % 60
    return f"{hours}h {minutes}m {seconds:.0f}s"

class WipeCLI:
    """Command-line interface for FastWipeEngine."""
    
    def __init__(self):
        self.engine = None
        self.last_update = 0
        self.start_time = 0
        
    def progress_callback(self, progress: WipeProgress):
        """Handle progress updates from the wipe engine."""
        current_time = time.time()
        
        # Throttle updates to prevent console spam
        if current_time - self.last_update < 0.1 and not progress.is_complete:
            return
            
        self.last_update = current_time
        
        # Calculate progress bar
        bar_width = 50
        filled = int(bar_width * progress.percent_complete / 100)
        bar = '#' * filled + '-' * (bar_width - filled)
        
        # Format status line
        status = []
        if progress.error:
            status.append(f"Error: {progress.error}")
        else:
            status.extend([
                f"{progress.percent_complete:.1f}% |{bar}| {format_size(progress.bytes_processed)} / {format_size(progress.total_bytes)}",
                f"Speed: {progress.speed_mbps:.1f} MB/s",
                f"Remaining: {format_time(progress.time_remaining) if progress.time_remaining > 0 else '--'}"
            ])
        
        # Print progress
        print('\r' + ' | '.join(status), end='', flush=True)
        
        if progress.is_complete or progress.error:
            print()
    
    def run(self, device_path: str, method: str, verify: bool = False):
        """Run the wipe operation."""
        if not os.path.exists(device_path):
            print(f"Error: Device {device_path} not found")
            return 1
        
        print(f"Starting wipe of {device_path} using {method} method")
        print("Press Ctrl+C to cancel\n")
        
        self.engine = FastWipeEngine(progress_callback=self.progress_callback)
        self.start_time = time.time()
        
        try:
            # Set up signal handler for graceful shutdown
            signal.signal(signal.SIGINT, self._signal_handler)
            
            # Start the wipe
            progress = self.engine.wipe_device(device_path, method, verify)
            
            # Print final status
            self._print_final_status(progress)
            
            return 0 if progress.is_complete else 1
            
        except Exception as e:
            print(f"\nError: {str(e)}")
            return 1
    
    def _signal_handler(self, signum, frame):
        """Handle interrupt signal (Ctrl+C)."""
        if self.engine:
            print("\nStopping wipe operation...")
            self.engine.stop()
    
    def _print_final_status(self, progress: WipeProgress):
        """Print final status after wipe completes."""
        elapsed = time.time() - self.start_time
        
        print("\n" + "=" * 60)
        
        if progress.is_complete:
            print("Wipe completed successfully!")
        else:
            print("Wipe was interrupted or failed")
        
        print(f"Time elapsed: {format_time(elapsed)}")
        print(f"Data processed: {format_size(progress.bytes_processed)}")
        
        if elapsed > 0:
            avg_speed = progress.bytes_processed / (1024 * 1024) / elapsed
            print(f"Average speed: {avg_speed:.1f} MB/s")
        
        if progress.error:
            print(f"Error: {progress.error}")
        
        print("=" * 60)

def main():
    """Main entry point for the CLI."""
    parser = argparse.ArgumentParser(description="High-performance disk wiping tool")
    parser.add_argument("device", help="Path to the device to wipe (e.g., /dev/sdX or \\\.\PhysicalDriveX)")
    parser.add_argument("-m", "--method", default="random",
                       choices=["random", "zeros", "ones"],
                       help="Wipe method (default: random)")
    parser.add_argument("-v", "--verify", action="store_true",
                       help="Verify the wipe after completion")
    
    args = parser.parse_args()
    
    if os.name == 'nt' and not args.device.startswith(r'\\.\'):
        args.device = fr"\\.\{args.device}"
    
    cli = WipeCLI()
    return cli.run(args.device, args.method, args.verify)

if __name__ == "__main__":
    sys.exit(main())
