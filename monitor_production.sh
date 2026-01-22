#!/bin/bash
# Armoricore Production Monitoring Script
# Monitors system health, services, and performance metrics
# Run this script periodically (e.g., via cron) for production monitoring

set -e

# Configuration
APP_NAME="armoricore-realtime"
APP_PORT=4000
NATS_PORT=4222
HEALTH_ENDPOINT="http://localhost:${APP_PORT}/api/v1/health"
LOG_FILE="/var/log/armoricore/monitoring.log"
ALERT_EMAIL="alerts@armoricore.com"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Logging functions
log_info() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') [INFO] $1" >> "$LOG_FILE"
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_warning() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') [WARNING] $1" >> "$LOG_FILE"
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') [ERROR] $1" >> "$LOG_FILE"
    echo -e "${RED}[ERROR]${NC} $1"
}

log_success() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') [SUCCESS] $1" >> "$LOG_FILE"
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

# Alert function
send_alert() {
    local subject="$1"
    local message="$2"
    local severity="${3:-warning}"

    log_error "ALERT: $subject - $message"

    # Send email alert (if mail is configured)
    if command -v mail >/dev/null 2>&1 && [ -n "$ALERT_EMAIL" ]; then
        echo "$message" | mail -s "[$severity] $APP_NAME Alert: $subject" "$ALERT_EMAIL"
    fi

    # Could also integrate with Slack, PagerDuty, etc.
    # curl -X POST -H 'Content-type: application/json' \
    #   --data "{\"text\":\"$APP_NAME Alert: $subject - $message\"}" \
    #   YOUR_SLACK_WEBHOOK_URL
}

# Health check functions
check_service_health() {
    local service_name="$1"
    local url="$2"
    local timeout="${3:-10}"

    log_info "Checking $service_name health at $url"

    if curl -f -s --max-time "$timeout" "$url" >/dev/null 2>&1; then
        log_success "$service_name is healthy"
        return 0
    else
        log_error "$service_name health check failed"
        send_alert "$service_name Unhealthy" "$service_name health check failed at $url" "error"
        return 1
    fi
}

check_port_open() {
    local host="$1"
    local port="$2"
    local service_name="$3"

    log_info "Checking if $service_name port $port is open on $host"

    if nc -z "$host" "$port" 2>/dev/null; then
        log_success "$service_name port $port is open"
        return 0
    else
        log_error "$service_name port $port is not accessible"
        send_alert "$service_name Port Closed" "$service_name port $port is not accessible on $host" "error"
        return 1
    fi
}

check_process_running() {
    local process_name="$1"
    local expected_count="${2:-1}"

    log_info "Checking if $expected_count $process_name process(es) are running"

    local actual_count
    actual_count=$(pgrep -f "$process_name" | wc -l)

    if [ "$actual_count" -ge "$expected_count" ]; then
        log_success "Found $actual_count $process_name process(es) running"
        return 0
    else
        log_error "Expected $expected_count $process_name process(es), found $actual_count"
        send_alert "Process Count Low" "Expected $expected_count $process_name process(es), found $actual_count" "warning"
        return 1
    fi
}

check_disk_space() {
    local mount_point="$1"
    local warning_threshold="${2:-80}"
    local critical_threshold="${3:-95}"

    log_info "Checking disk space on $mount_point"

    local usage
    usage=$(df "$mount_point" | tail -1 | awk '{print $5}' | sed 's/%//')

    if [ "$usage" -ge "$critical_threshold" ]; then
        log_error "Critical disk usage on $mount_point: ${usage}%"
        send_alert "Disk Space Critical" "Disk usage on $mount_point is ${usage}%" "error"
        return 1
    elif [ "$usage" -ge "$warning_threshold" ]; then
        log_warning "High disk usage on $mount_point: ${usage}%"
        send_alert "Disk Space Warning" "Disk usage on $mount_point is ${usage}%" "warning"
        return 0
    else
        log_success "Disk usage on $mount_point: ${usage}%"
        return 0
    fi
}

check_memory_usage() {
    log_info "Checking system memory usage"

    local mem_usage
    mem_usage=$(free | grep Mem | awk '{printf "%.0f", $3/$2 * 100.0}')

    if [ "$mem_usage" -ge 90 ]; then
        log_error "High memory usage: ${mem_usage}%"
        send_alert "High Memory Usage" "System memory usage is ${mem_usage}%" "error"
        return 1
    elif [ "$mem_usage" -ge 75 ]; then
        log_warning "Moderate memory usage: ${mem_usage}%"
        return 0
    else
        log_success "Memory usage: ${mem_usage}%"
        return 0
    fi
}

check_cpu_usage() {
    log_info "Checking system CPU usage"

    local cpu_usage
    cpu_usage=$(top -bn1 | grep "Cpu(s)" | sed "s/.*, *\([0-9.]*\)%* id.*/\1/" | awk '{print 100 - $1}')

    if [ "$(echo "$cpu_usage > 90" | bc -l)" -eq 1 ]; then
        log_error "High CPU usage: ${cpu_usage}%"
        send_alert "High CPU Usage" "System CPU usage is ${cpu_usage}%" "error"
        return 1
    elif [ "$(echo "$cpu_usage > 75" | bc -l)" -eq 1 ]; then
        log_warning "Moderate CPU usage: ${cpu_usage}%"
        return 0
    else
        log_success "CPU usage: ${cpu_usage}%"
        return 0
    fi
}

check_database_connections() {
    log_info "Checking database connection status"

    # This assumes you have a database health check script
    # You could also use pg_isready or a simple query
    if command -v pg_isready >/dev/null 2>&1; then
        if pg_isready -h localhost >/dev/null 2>&1; then
            log_success "Database is accepting connections"
            return 0
        else
            log_error "Database is not accepting connections"
            send_alert "Database Down" "Database is not accepting connections" "error"
            return 1
        fi
    else
        log_warning "pg_isready not available, skipping database check"
        return 0
    fi
}

# Main monitoring function
main() {
    log_info "Starting $APP_NAME production monitoring"

    local failed_checks=0

    # System resource checks
    check_disk_space "/" || ((failed_checks++))
    check_memory_usage || ((failed_checks++))
    check_cpu_usage || ((failed_checks++))

    # Service availability checks
    check_port_open "localhost" "$APP_PORT" "$APP_NAME" || ((failed_checks++))
    check_port_open "localhost" "$NATS_PORT" "NATS" || ((failed_checks++))

    # Process checks
    check_process_running "beam.smp" 1 || ((failed_checks++))  # Elixir/Erlang VM
    check_process_running "nats-server" 1 || ((failed_checks++))  # NATS server

    # Health endpoint checks
    check_service_health "$APP_NAME" "$HEALTH_ENDPOINT" || ((failed_checks++))

    # Database checks
    check_database_connections || ((failed_checks++))

    # Summary
    if [ "$failed_checks" -eq 0 ]; then
        log_success "All monitoring checks passed"
        exit 0
    else
        log_error "$failed_checks monitoring check(s) failed"
        exit 1
    fi
}

# Run main function
main "$@"