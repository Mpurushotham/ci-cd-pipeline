#!/bin/bash
################################################################################
# CI/CD Pipeline Script for DevSecOps with Auto-Installation of Tools
#
# This script orchestrates a CI/CD pipeline that integrates multiple stages:
#   - Talisman secret scan
#   - OWASP Dependency-Check vulnerability scan
#   - Python unit tests execution
#   - Terraform IaC validation and planning
#   - Ansible playbook execution for OS configuration
#   - SonarQube analysis
#   - Docker image build and container vulnerability scans (Trivy & Snyk)
#   - Static (SAST) and Dynamic (DAST via OWASP ZAP) security testing
#   - Jenkins job triggering
#   - Monitoring setup using Prometheus & Grafana
#   - Application deployment to Kubernetes
#
# This version checks if tools are installed and attempts to install them
# (or prompts you for manual installation) if not found.
#
# Usage:
#   1. Make executable:
#         chmod +x ci_cd_pipeline.sh
#
#   2. Execute the entire pipeline:
#         ./ci_cd_pipeline.sh
#
#   3. Execute a specific stage (e.g., Terraform validation):
#         ./ci_cd_pipeline.sh -s terraform
#
#   4. For help:
#         ./ci_cd_pipeline.sh -h
#
# Note:
#   Some installation steps might require manual intervention (e.g., sonar-scanner).
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
# Function: check_and_install_tool
# Description: Check if a tool is installed; if not, attempt installation or prompt manual install.
#
# Parameters:
#   $1 - command name to check
#   $2 - installation command (should be wrapped in quotes)
##############################
check_and_install_tool() {
    local tool_name="$1"
    local install_command="$2"
    echo "Checking if $tool_name is installed..."
    if ! command -v "$tool_name" &> /dev/null; then
        echo "$tool_name not found. Attempting to install $tool_name..."
        eval "$install_command"
        # Pause briefly to let installation finish
        sleep 2
        if ! command -v "$tool_name" &> /dev/null; then
            echo "Failed to install $tool_name. Please install it manually and re-run the script."
            exit 1
        else
            echo "$tool_name installed successfully."
        fi
    else
        echo "$tool_name is already installed."
    fi
}

##############################
# Function: run_talisman
# Description: Run Talisman to scan for secrets in the repository.
##############################
run_talisman() {
    log_info "Running Talisman scan to detect potential secrets in code..."
    check_and_install_tool "talisman" "pip3 install talisman"  # Attempt installation via pip3
    # Scan current directory for secrets.
    talisman --scan .
    log_info "Talisman scan completed."
}

##############################
# Function: run_dependency_check
# Description: Run OWASP Dependency Check for vulnerable dependencies.
##############################
run_dependency_check() {
    log_info "Running Dependency Check for vulnerable dependencies..."
    check_and_install_tool "dependency-check" "sudo snap install dependency-check || echo 'Please install dependency-check manually from https://github.com/jeremylong/DependencyCheck'" 
    # Generate an HTML report by scanning the current directory.
    dependency-check --project "My Project" --out ./dependency-check-report.html --scan .
    log_info "Dependency check completed. Report generated at dependency-check-report.html."
}

##############################
# Function: run_python_tests
# Description: Execute Python unit tests using unittest discovery.
##############################
run_python_tests() {
    log_info "Running Python unit tests..."
    check_and_install_tool "python3" "sudo apt install python3 -y"
    # Discover and run tests in the 'tests' directory.
    python3 -m unittest discover -s tests
    log_info "Python tests completed."
}

##############################
# Function: run_terraform
# Description: Validate and create a plan for Terraform IaC code.
##############################
run_terraform() {
    log_info "Running Terraform configuration validation..."
    check_and_install_tool "terraform" "sudo snap install terraform --classic"
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
    check_and_install_tool "ansible-playbook" "sudo apt install ansible -y"
    # Assumes the inventory file (inventory.ini) and playbook (playbook.yml) exist.
    ansible-playbook -i inventory.ini playbook.yml
    log_info "Ansible playbook executed successfully."
}

##############################
# Function: run_sonar_analysis
# Description: Run SonarQube analysis using sonar-scanner.
##############################
run_sonar_analysis() {
    log_info "Starting SonarQube analysis..."
    check_and_install_tool "sonar-scanner" "echo 'Please install sonar-scanner manually from https://docs.sonarqube.org/latest/analysis/scan/sonarscanner/'; exit 1"
    # Run the sonar-scanner with default configuration; customize as necessary.
    sonar-scanner
    log_info "SonarQube analysis completed."
}

##############################
# Function: run_docker_build_and_scan
# Description: Build a Docker image and perform vulnerability scans.
##############################
run_docker_build_and_scan() {
    log_info "Starting Docker image build..."
    check_and_install_tool "docker" "sudo apt install docker.io -y && sudo systemctl start docker && sudo systemctl enable docker"
    local image_tag="myapp:latest"  # Docker image tag
    docker build -t "$image_tag" .
    log_info "Docker image built with tag: $image_tag."

    # Scan the Docker image with Trivy.
    log_info "Scanning Docker image with Trivy..."
    check_and_install_tool "trivy" "wget -qO- https://aquasecurity.github.io/trivy-repo/deb/public.key | sudo apt-key add - && echo deb https://aquasecurity.github.io/trivy-repo/deb stable main | sudo tee /etc/apt/sources.list.d/trivy.list && sudo apt update && sudo apt install trivy -y"
    trivy image "$image_tag"

    # Scan the Docker image with Snyk.
    log_info "Scanning Docker image with Snyk..."
    # Ensure Node.js and npm are installed for Snyk installation.
    check_and_install_tool "node" "sudo apt install nodejs -y"
    check_and_install_tool "npm" "sudo apt install npm -y"
    check_and_install_tool "snyk" "sudo npm install -g snyk"
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
    echo "Running SAST scan... (please replace with your SAST tool command)"
    log_info "SAST scan completed."
}

##############################
# Function: run_dast
# Description: Execute Dynamic Application Security Testing (DAST)
#              using OWASP ZAP.
##############################
run_dast() {
    log_info "Starting DAST scan..."
    check_and_install_tool "zap-baseline.py" "echo 'Please install OWASP ZAP from https://www.zaproxy.org/download/ and ensure zap-baseline.py is in your PATH'; exit 1"
    local target_url="http://localhost"  # Adjust this URL as needed
    zap-baseline.py -t "$target_url"
    log_info "DAST scan completed using OWASP ZAP."
}

##############################
# Function: trigger_jenkins_job
# Description: Trigger a Jenkins job via the CLI or REST API securely.
##############################
trigger_jenkins_job() {
    log_info "Triggering Jenkins build job..."
    # For Jenkins, you must have the CLI or credentials set up.
    echo "Triggering Jenkins job via Jenkins CLI or REST API... (please configure your Jenkins integration)"
    log_info "Jenkins job triggered."
}

##############################
# Function: monitoring_setup
# Description: Configure monitoring using Prometheus and Grafana.
##############################
monitoring_setup() {
    log_info "Setting up monitoring with Prometheus and Grafana..."
    # Placeholder: Typically, you may deploy/update Helm charts or manifests.
    echo "Configuring Prometheus and Grafana dashboards... (please configure as needed)"
    log_info "Monitoring tools configuration completed."
}

##############################
# Function: deploy_kubernetes
# Description: Deploy the application to a Kubernetes cluster.
##############################
deploy_kubernetes() {
    log_info "Deploying application to Kubernetes..."
    check_and_install_tool "kubectl" "sudo snap install kubectl --classic"
    # Assumes Kubernetes manifests reside in the 'k8s' directory.
    kubectl apply -f k8s/deployment.yml
    log_info "Application deployed to Kubernetes."
}

##############################
# Main: Orchestrate Pipeline Execution
# Description: Execute functions based on the chosen stage.
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
