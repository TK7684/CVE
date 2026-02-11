"""
Debug System Module.
Provides debugging utilities, profiling, and tracing capabilities.
"""
import time
import functools
import traceback
import cProfile
import pstats
import io
import threading
from datetime import datetime
from pathlib import Path
from typing import Optional, Callable, Any, Dict
from dataclasses import dataclass, field
from contextlib import contextmanager

from config.settings import settings
from core.logger import log, console


@dataclass
class DebugConfig:
    """Debug system configuration."""
    enabled: bool = True
    profiling_enabled: bool = False
    trace_enabled: bool = False
    verbose: bool = False
    log_to_file: bool = True
    log_file: Optional[Path] = None


@dataclass
class ProfileResult:
    """Results from a profiled function."""
    function_name: str
    total_time_ms: float
    call_count: int
    avg_time_ms: float
    stats_summary: str


@dataclass
class TraceEntry:
    """A single trace log entry."""
    timestamp: str
    thread_id: int
    function: str
    event: str  # 'enter', 'exit', 'error'
    duration_ms: Optional[float] = None
    error: Optional[str] = None


class DebugSystem:
    """
    Comprehensive debugging utilities for the pipeline.
    Includes profiling, tracing, and diagnostic tools.
    """
    
    def __init__(self, config: Optional[DebugConfig] = None):
        self.config = config or DebugConfig()
        self.traces: list[TraceEntry] = []
        self.profiles: Dict[str, ProfileResult] = {}
        self._lock = threading.Lock()
        
        # Setup log file
        if self.config.log_to_file:
            self.config.log_file = settings.DATA_DIR / "debug.log"
    
    def enable(self):
        """Enables the debug system."""
        self.config.enabled = True
        log.info("[Debug] Debug system enabled")
    
    def disable(self):
        """Disables the debug system."""
        self.config.enabled = False
    
    # ==================== TIMING DECORATORS ====================
    
    def timed(self, func: Callable) -> Callable:
        """
        Decorator to measure function execution time.
        Usage: @debugger.timed
        """
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            if not self.config.enabled:
                return func(*args, **kwargs)
            
            start = time.perf_counter()
            try:
                result = func(*args, **kwargs)
                duration = (time.perf_counter() - start) * 1000
                
                if self.config.verbose:
                    log.debug(f"[Debug] {func.__name__} completed in {duration:.2f}ms")
                
                return result
            except Exception as e:
                duration = (time.perf_counter() - start) * 1000
                log.error(f"[Debug] {func.__name__} failed after {duration:.2f}ms: {e}")
                raise
        
        return wrapper
    
    def traced(self, func: Callable) -> Callable:
        """
        Decorator to trace function entry/exit.
        Usage: @debugger.traced
        """
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            if not self.config.enabled or not self.config.trace_enabled:
                return func(*args, **kwargs)
            
            thread_id = threading.get_ident()
            func_name = f"{func.__module__}.{func.__name__}"
            
            # Log entry
            self._add_trace(func_name, "enter", thread_id)
            
            start = time.perf_counter()
            try:
                result = func(*args, **kwargs)
                duration = (time.perf_counter() - start) * 1000
                self._add_trace(func_name, "exit", thread_id, duration=duration)
                return result
            except Exception as e:
                duration = (time.perf_counter() - start) * 1000
                self._add_trace(func_name, "error", thread_id, duration=duration, error=str(e))
                raise
        
        return wrapper
    
    def profiled(self, func: Callable) -> Callable:
        """
        Decorator to profile function with cProfile.
        Usage: @debugger.profiled
        """
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            if not self.config.enabled or not self.config.profiling_enabled:
                return func(*args, **kwargs)
            
            profiler = cProfile.Profile()
            profiler.enable()
            
            try:
                result = func(*args, **kwargs)
            finally:
                profiler.disable()
                
                # Capture stats
                stream = io.StringIO()
                stats = pstats.Stats(profiler, stream=stream)
                stats.sort_stats("cumulative")
                stats.print_stats(20)  # Top 20 functions
                
                # Store profile result
                self.profiles[func.__name__] = ProfileResult(
                    function_name=func.__name__,
                    total_time_ms=sum(s[2] for s in profiler.getstats()) * 1000,
                    call_count=sum(s[1] for s in profiler.getstats()),
                    avg_time_ms=0,  # Calculated if needed
                    stats_summary=stream.getvalue()
                )
            
            return result
        
        return wrapper
    
    # ==================== CONTEXT MANAGERS ====================
    
    @contextmanager
    def timer(self, label: str):
        """
        Context manager for timing code blocks.
        Usage: with debugger.timer("operation"):
        """
        start = time.perf_counter()
        try:
            yield
        finally:
            duration = (time.perf_counter() - start) * 1000
            if self.config.verbose:
                log.info(f"[Timer] {label}: {duration:.2f}ms")
    
    @contextmanager
    def catch_and_log(self, operation: str, reraise: bool = True):
        """
        Context manager to catch and log exceptions.
        Usage: with debugger.catch_and_log("operation"):
        """
        try:
            yield
        except Exception as e:
            log.error(f"[Debug] Error in {operation}: {e}")
            if self.config.verbose:
                log.error(traceback.format_exc())
            if reraise:
                raise
    
    # ==================== TRACE MANAGEMENT ====================
    
    def _add_trace(
        self,
        function: str,
        event: str,
        thread_id: int,
        duration: Optional[float] = None,
        error: Optional[str] = None
    ):
        """Adds a trace entry."""
        entry = TraceEntry(
            timestamp=datetime.utcnow().isoformat(),
            thread_id=thread_id,
            function=function,
            event=event,
            duration_ms=duration,
            error=error
        )
        
        with self._lock:
            self.traces.append(entry)
            
            # Keep only last 1000 traces
            if len(self.traces) > 1000:
                self.traces = self.traces[-1000:]
    
    def get_traces(self, limit: int = 100) -> list[TraceEntry]:
        """Returns recent traces."""
        with self._lock:
            return self.traces[-limit:]
    
    def clear_traces(self):
        """Clears all traces."""
        with self._lock:
            self.traces.clear()
    
    # ==================== DIAGNOSTIC TOOLS ====================
    
    def dump_state(self) -> Dict[str, Any]:
        """Dumps current debug state for diagnostics."""
        return {
            "config": {
                "enabled": self.config.enabled,
                "profiling": self.config.profiling_enabled,
                "tracing": self.config.trace_enabled,
                "verbose": self.config.verbose
            },
            "traces_count": len(self.traces),
            "profiles_count": len(self.profiles),
            "last_trace": self.traces[-1] if self.traces else None
        }
    
    def print_profile(self, function_name: str):
        """Prints profile results for a function."""
        if function_name in self.profiles:
            result = self.profiles[function_name]
            console.print(f"\n[bold]Profile: {result.function_name}[/bold]")
            console.print(f"Total Time: {result.total_time_ms:.2f}ms")
            console.print(f"Call Count: {result.call_count}")
            console.print(f"\n{result.stats_summary}")
        else:
            log.warning(f"No profile found for: {function_name}")
    
    def memory_usage(self) -> Dict[str, int]:
        """Returns current memory usage."""
        import sys
        
        return {
            "traces_size": sys.getsizeof(self.traces),
            "profiles_size": sys.getsizeof(self.profiles),
            "total_estimated": sys.getsizeof(self.traces) + sys.getsizeof(self.profiles)
        }


# Global instance
debugger = DebugSystem()
