#!/bin/bash
################################################################################
# CI/CD Pipeline Script for DevSecOps
#
# This script orchestrates a CI/CD pipeline that integrates:
#   - Code scanning for secrets using Talisman
#   - Vulnerability scanning with OWASP Dependency-Check
#   - Python unit tests execution
#   - Infrastructure validation using Terraform (IaC)
#   - OS configurations via Ansible playbook
#   - Code quality analysis through SonarQube
#   - Docker image build and scanning (Trivy and Snyk)
#   - Static (SAST) and Dynamic (DAST using OWASP ZAP) security testing
#   - Jenkins job triggering and GitHub integration
#   - Monitoring configuration setup using Prometheus & Grafana
#   - Deployment of the application to Kubernetes
#
# Usage:
#   1. Make executable:
#         chmod +x ci_cd_pipeline.sh
#
#   2. To execute the entire pipeline:
#         ./ci_cd_pipeline.sh
#
#   3. To execute a specific stage (example: Terraform validation):
#         ./ci_cd_pipeline.sh -s terraform
#
#   4. For help:
#         ./ci_cd_pipeline.sh -h
#
# Note:
#   This script assumes all required tools (Python3, Terraform, Ansible, Docker,
#   Talisman, dependency-check, sonar-scanner, trivy, snyk, zap-baseline.py,
#   kubectl, etc.) are installed and available in the $PATH.
################################################################################

# Exit immediately if a command exits with a non-zero status,
# if an undefined variable is used, or if a command in a pipeline fails.
set -euo pipefail

##############################
# Global Variables & Defaults
##############################
SCRIPT_NAME=$(basename "$0")   # Script name for logging and messages
PIPELINE_STAGE="all"           # Default stage to execute (all stages)

##############################
# Function: usage
# Description: Provide help information on how to use the script.
##############################
usage() {
    cat <<EOF
Usage: $SCRIPT_NAME [-h|--help] [-s|--stage stage]

Options:
  -h, --help            Show this help message and exit.
  -s, --stage stage     Execute a specific stage of the pipeline.
                        Available stages:
                          all         Execute all pipeline stages (default)
                          talisman    Run Talisman secret scan
                          dependency  Run dependency-check scan
                          python      Run Python unit tests
                          terraform   Validate and plan Terraform IaC
                          ansible     Execute Ansible playbook for OS configs
                          sonar       Run SonarQube analysis
                          docker      Build Docker image and scan it
                          sast        Run Static Application Security Testing (SAST)
                          dast        Run Dynamic Application Security Testing (DAST)
                          jenkins     Trigger a Jenkins job
                          monitoring  Setup monitoring (Prometheus & Grafana)
                          deploy      Deploy application to Kubernetes

EOF
    exit 0
}

##############################
# Command-line Options Parsing
##############################
while [[ $# -gt 0 ]]; do
    key="$1"
    case $key in
        -h|--help)
            usage
            ;;
        -s|--stage)
            PIPELINE_STAGE="$2"  # User-specified pipeline stage
            shift  # Consume the option flag
            shift  # Consume the stage value
            ;;
        *)
            echo "Unknown option: $1"
            usage
            ;;
    esac
done

##############################
# Function: log_info
# Description: Log a message with a timestamp.
##############################
log_info() {
    local message="$1"
    echo "$(date '+%Y-%m-%d %H:%M:%S') [INFO] $message"
}

##############################
# Function: run_talisman
# Description: Run Talisman for secret detection in the repository.
##############################
run_talisman() {
    log_info "Running Talisman scan to detect potential secrets in code..."
    if ! command -v talisman &> /dev/null; then
        echo "Talisman not installed. Please install talisman to proceed."
        exit 1
    fi
    # Scan current directory for secrets
    talisman --scan .
    log_info "Talisman scan completed."
}

##############################
# Function: run_dependency_check
# Description: Run OWASP Dependency Check to scan for vulnerable dependencies.
##############################
run_dependency_check() {
    log_info "Running Dependency Check for vulnerable dependencies..."
    if ! command -v dependency-check &> /dev/null; then
        echo "dependency-check is not installed. Please install it to proceed."
        exit 1
    fi
    # Generate an HTML report by scanning the current directory
    dependency-check --project "My Project" --out ./dependency-check-report.html --scan .
    log_info "Dependency check completed. Report generated at dependency-check-report.html."
}

##############################
# Function: run_python_tests
# Description: Execute Python unit tests using unittest discovery.
##############################
run_python_tests() {
    log_info "Running Python unit tests..."
    if ! command -v python3 &> /dev/null; then
        echo "python3 is not installed. Please install Python 3."
        exit 1
    fi
    # Discover and run tests in the 'tests' directory
    python3 -m unittest discover -s tests
    log_info "Python tests completed."
}

##############################
# Function: run_terraform
# Description: Validate and create a plan for Terraform IaC code.
##############################
run_terraform() {
    log_info "Running Terraform configuration validation..."
    if ! command -v terraform &> /dev/null; then
        echo "Terraform is not installed. Please install Terraform."
        exit 1
    fi
    # Initialize, validate, and plan Terraform configuration non-interactively.
    terraform init -input=false
    terraform validate
    terraform plan -out=tfplan.out
    log_info "Terraform configuration validated and plan created."
}

##############################
# Function: run_ansible
# Description: Execute an Ansible playbook for OS configurations.
##############################
run_ansible() {
    log_info "Executing Ansible playbook for OS configurations..."
    if ! command -v ansible-playbook &> /dev/null; then
        echo "Ansible not installed. Please install Ansible."
        exit 1
    fi
    # Assumes the inventory file (inventory.ini) and playbook (playbook.yml) exist
    ansible-playbook -i inventory.ini playbook.yml
    log_info "Ansible playbook executed successfully."
}

##############################
# Function: run_sonar_analysis
# Description: Run SonarQube analysis using sonar-scanner.
##############################
run_sonar_analysis() {
    log_info "Starting SonarQube analysis..."
    if ! command -v sonar-scanner &> /dev/null; then
        echo "sonar-scanner not installed. Please install SonarQube scanner."
        exit 1
    fi
    # Run the sonar-scanner with default configuration; customize as necessary.
    sonar-scanner
    log_info "SonarQube analysis completed."
}

##############################
# Function: run_docker_build_and_scan
# Description: Build a Docker image and perform vulnerability scans using Trivy and Snyk.
##############################
run_docker_build_and_scan() {
    log_info "Starting Docker image build..."
    if ! command -v docker &> /dev/null; then
        echo "docker is not installed. Please install Docker."
        exit 1
    fi
    local image_tag="myapp:latest"  # Docker image tag
    docker build -t "$image_tag" .
    log_info "Docker image built with tag: $image_tag."

    # Scan the Docker image with Trivy
    log_info "Scanning Docker image with Trivy..."
    if ! command -v trivy &> /dev/null; then
        echo "trivy is not installed. Please install Trivy."
        exit 1
    fi
    trivy image "$image_tag"

    # Scan the Docker image with Snyk
    log_info "Scanning Docker image with Snyk..."
    if ! command -v snyk &> /dev/null; then
        echo "snyk is not installed. Please install Snyk."
        exit 1
    fi
    snyk container test "$image_tag"
    log_info "Docker image scanning completed."
}

##############################
# Function: run_sast
# Description: Execute Static Application Security Testing (SAST).
##############################
run_sast() {
    log_info "Starting SAST scan..."
    # Placeholder command: Replace with your SAST tool's command.
    echo "Running SAST scan..."
    log_info "SAST scan completed."
}

##############################
# Function: run_dast
# Description: Execute Dynamic Application Security Testing (DAST)
#              using OWASP ZAP.
##############################
run_dast() {
    log_info "Starting DAST scan..."
    if ! command -v zap-baseline.py &> /dev/null; then
        echo "OWASP ZAP baseline script not found. Please install OWASP ZAP."
        exit 1
    fi
    # Define the target URL for scanning (adjust as needed)
    local target_url="http://localhost"
    zap-baseline.py -t "$target_url"
    log_info "DAST scan completed using OWASP ZAP."
}

##############################
# Function: trigger_jenkins_job
# Description: Trigger a Jenkins job via the CLI or REST API securely.
##############################
trigger_jenkins_job() {
    log_info "Triggering Jenkins build job..."
    # Placeholder: Replace with actual Jenkins CLI or API token-secured call.
    echo "Triggering Jenkins job via Jenkins CLI or REST API..."
    log_info "Jenkins job triggered."
}

##############################
# Function: monitoring_setup
# Description: Configure monitoring using Prometheus and Grafana.
##############################
monitoring_setup() {
    log_info "Setting up monitoring with Prometheus and Grafana..."
    # Placeholder: In production, this may involve deploying/updating Helm charts or manifests.
    echo "Configuring Prometheus and Grafana dashboards..."
    log_info "Monitoring tools configuration completed."
}

##############################
# Function: deploy_kubernetes
# Description: Deploy the application to a Kubernetes cluster.
##############################
deploy_kubernetes() {
    log_info "Deploying application to Kubernetes..."
    if ! command -v kubectl &> /dev/null; then
        echo "kubectl is not installed. Please install kubectl."
        exit 1
    fi
    # Assumes Kubernetes manifests are maintained in the 'k8s' directory.
    kubectl apply -f k8s/deployment.yml
    log_info "Application deployed to Kubernetes."
}

##############################
# Main: Orchestrate Pipeline Execution
# Description: Based on the selected stage, execute the corresponding functions.
##############################
main() {
    log_info "Starting CI/CD pipeline execution..."
    case "$PIPELINE_STAGE" in
        all)
            run_talisman
            run_dependency_check
            run_python_tests
            run_terraform
            run_ansible
            run_sonar_analysis
            run_docker_build_and_scan
            run_sast
            run_dast
            trigger_jenkins_job
            monitoring_setup
            deploy_kubernetes
            ;;
        talisman)
            run_talisman
            ;;
        dependency)
            run_dependency_check
            ;;
        python)
            run_python_tests
            ;;
        terraform)
            run_terraform
            ;;
        ansible)
            run_ansible
            ;;
        sonar)
            run_sonar_analysis
            ;;
        docker)
            run_docker_build_and_scan
            ;;
        sast)
            run_sast
            ;;
        dast)
            run_dast
            ;;
        jenkins)
            trigger_jenkins_job
            ;;
        monitoring)
            monitoring_setup
            ;;
        deploy)
            deploy_kubernetes
            ;;
        *)
            echo "Invalid stage option provided: $PIPELINE_STAGE"
            usage
            ;;
    esac
    log_info "CI/CD pipeline execution completed."
}

##############################
# Script Entry Point
##############################
main
