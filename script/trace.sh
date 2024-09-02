#!/bin/bash

TRACING=/sys/kernel/tracing/

# echo tcp_* > ${TRACING}/set_ftrace_filter
# echo tcp_release_cb > ${TRACING}/set_ftrace_notrace
echo > ${TRACING}/set_ftrace_filter
echo function_graph > ${TRACING}/current_tracer
cat servers.pid > ${TRACING}/set_ftrace_pid
# echo > ${TRACING}/set_ftrace_pid
cat ${TRACING}/trace_pipe