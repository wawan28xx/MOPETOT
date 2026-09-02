pipeline {
    agent { label 'k3s-platform-prod-kubeconfig' }

    options {
        skipDefaultCheckout(true)
        disableConcurrentBuilds()
        timestamps()
        buildDiscarder(logRotator(numToKeepStr: '20'))
        timeout(time: 45, unit: 'MINUTES')
    }

    triggers {
        githubPush()
        pollSCM('H/5 * * * *')
    }

    environment {
        APP_NAME = 'mopetot'
        NAMESPACE = 'platform-prod'
        KUBECONFIG = '/home/deit/.kube/mopetot-config'
        CONTAINER_NAME = "mopetot-ci-${BUILD_NUMBER}"
    }

    stages {
        stage('Checkout master') {
            steps {
                checkout scm
                script {
                    def revision = sh(
                        script: 'git rev-parse --short=12 HEAD',
                        returnStdout: true
                    ).trim()
                    env.IMAGE_TAG = "${revision}-jenkins${env.BUILD_NUMBER}"
                    env.LOCAL_IMAGE = "${env.APP_NAME}:${env.IMAGE_TAG}"
                }
            }
        }

        stage('Build image') {
            steps {
                sh '''
                    set -eu
                    docker build --pull --target runtime --tag "$LOCAL_IMAGE" .
                '''
            }
        }

        stage('Application tests') {
            steps {
                sh '''
                    set -eu
                    docker run --rm --entrypoint python "$LOCAL_IMAGE" \
                        -m compileall -q mobile_audit.py apkid_wrapper.py \
                        secret_scanner.py engines web
                    docker run --rm --entrypoint python "$LOCAL_IMAGE" \
                        -m unittest discover -s web -p 'test_production.py'
                '''
            }
        }

        stage('Container smoke test') {
            steps {
                sh '''
                    set -eu
                    docker run --detach --name "$CONTAINER_NAME" "$LOCAL_IMAGE"
                    trap 'docker logs "$CONTAINER_NAME" || true; docker rm --force --volumes "$CONTAINER_NAME" >/dev/null 2>&1 || true' EXIT INT TERM

                    attempt=0
                    while [ "$attempt" -lt 30 ]; do
                        status=$(docker inspect --format='{{.State.Health.Status}}' "$CONTAINER_NAME")
                        if [ "$status" = "healthy" ]; then
                            exit 0
                        fi
                        if [ "$status" = "unhealthy" ]; then
                            echo "Container became unhealthy" >&2
                            exit 1
                        fi
                        attempt=$((attempt + 1))
                        sleep 2
                    done

                    echo "Container did not become healthy in time" >&2
                    exit 1
                '''
            }
        }

        stage('Import image to k3s') {
            steps {
                sh 'docker save "$LOCAL_IMAGE" | sudo -n k3s ctr images import -'
            }
        }

        stage('Deploy to k3s') {
            steps {
                sh '''
                    set -eu
                    previous_image="$(
                        kubectl -n "$NAMESPACE" get deployment "$APP_NAME" \
                            -o jsonpath='{.spec.template.spec.containers[0].image}'
                    )"
                    previous_retention_image="$(
                        kubectl -n "$NAMESPACE" get cronjob mopetot-retention \
                            -o jsonpath='{.spec.jobTemplate.spec.template.spec.containers[0].image}'
                    )"
                    rollback_needed=0

                    wait_rollout() {
                        attempt=0
                        while [ "$attempt" -lt 120 ]; do
                            deployment_json="$(
                                kubectl -n "$NAMESPACE" get deployment "$APP_NAME" -o json
                            )"
                            if printf '%s' "$deployment_json" | jq -e '
                                (.metadata.generation <= (.status.observedGeneration // 0)) and
                                (.status.updatedReplicas // 0) == .spec.replicas and
                                (.status.availableReplicas // 0) == .spec.replicas and
                                (.status.unavailableReplicas // 0) == 0
                            ' >/dev/null; then
                                return 0
                            fi
                            if printf '%s' "$deployment_json" | jq -e '
                                any(
                                    .status.conditions[]?;
                                    .type == "Progressing" and
                                    .reason == "ProgressDeadlineExceeded"
                                )
                            ' >/dev/null; then
                                return 1
                            fi
                            attempt=$((attempt + 1))
                            sleep 5
                        done
                        return 1
                    }

                    rollback() {
                        rollback_needed=0
                        echo "Deployment validation failed; restoring ${previous_image}" >&2
                        kubectl -n "$NAMESPACE" set image cronjob/mopetot-retention \
                            "retention=$previous_retention_image" || true
                        kubectl -n "$NAMESPACE" set image deployment/"$APP_NAME" \
                            "$APP_NAME=$previous_image" || true
                        wait_rollout || true
                    }

                    trap 'status=$?; if [ "$rollback_needed" = "1" ]; then rollback; fi; exit "$status"' EXIT
                    trap 'exit 130' INT
                    trap 'exit 143' TERM

                    rollback_needed=1
                    kubectl -n "$NAMESPACE" set image cronjob/mopetot-retention \
                        "retention=$LOCAL_IMAGE"
                    kubectl -n "$NAMESPACE" set image deployment/"$APP_NAME" \
                        "$APP_NAME=$LOCAL_IMAGE"

                    if ! wait_rollout; then
                        exit 1
                    fi

                    if ! curl --fail --silent --show-error --max-time 30 \
                        -H 'Host: mopetot.pentest.web.id' \
                        http://127.0.0.1/healthz >/dev/null; then
                        exit 1
                    fi

                    public_ip="$(
                        curl --fail --silent --show-error \
                            -H 'accept: application/dns-json' \
                            'https://cloudflare-dns.com/dns-query?name=mopetot.pentest.web.id&type=A' |
                            jq -r '.Answer[]? | select(.type == 1) | .data' |
                            head -n 1
                    )"
                    if [ -z "$public_ip" ] || ! curl \
                        --fail --silent --show-error --max-time 30 \
                        --resolve "mopetot.pentest.web.id:443:$public_ip" \
                        https://mopetot.pentest.web.id/healthz >/dev/null; then
                        exit 1
                    fi
                    rollback_needed=0
                '''
            }
        }
    }

    post {
        always {
            sh 'docker rm --force --volumes "$CONTAINER_NAME" >/dev/null 2>&1 || true'
            sh 'test -z "${LOCAL_IMAGE:-}" || docker image rm "$LOCAL_IMAGE" >/dev/null 2>&1 || true'
            cleanWs()
        }
        success {
            echo 'MOPETOT production deployment completed successfully'
        }
        failure {
            echo 'MOPETOT build or deployment failed; inspect this build log'
        }
    }
}
