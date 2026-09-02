pipeline {
    agent any

    options {
        skipDefaultCheckout(true)
        disableConcurrentBuilds(abortPrevious: true)
        timestamps()
        timeout(time: 45, unit: 'MINUTES')
    }

    parameters {
        booleanParam(
            name: 'PUBLISH_IMAGE',
            defaultValue: false,
            description: 'Publish the image on main/master or tag builds.'
        )
        string(
            name: 'PYTHON_BIN',
            defaultValue: 'python3.13',
            description: 'Python 3.12+ executable available on the Jenkins agent.'
        )
        string(
            name: 'DOCKER_REGISTRY',
            defaultValue: 'https://index.docker.io/v1/',
            description: 'Registry URL used by docker login.'
        )
        string(
            name: 'DOCKER_IMAGE',
            defaultValue: 'mopenot/mopenot',
            description: 'Target image repository, without a tag.'
        )
        string(
            name: 'DOCKER_CREDENTIALS_ID',
            defaultValue: 'docker-registry-credentials',
            description: 'Jenkins username/password credential ID.'
        )
    }

    environment {
        VENV_DIR = '.ci-venv'
        LOCAL_IMAGE = "mopenot:${BUILD_NUMBER}"
        CONTAINER_NAME = "mopenot-ci-${BUILD_NUMBER}"
    }

    stages {
        stage('Checkout') {
            steps {
                checkout scm
            }
        }

        stage('Python checks') {
            steps {
                sh '''
                    set -eu
                    "$PYTHON_BIN" -m venv "$VENV_DIR"
                    "$VENV_DIR/bin/python" -m pip install --upgrade pip
                    "$VENV_DIR/bin/python" -m pip install -r web/requirements.txt
                    "$VENV_DIR/bin/python" -m compileall -q \
                        mobile_audit.py apkid_wrapper.py secret_scanner.py engines web
                '''
            }
        }

        stage('Application smoke test') {
            steps {
                sh '''
                    set -eu
                    "$VENV_DIR/bin/python" -m uvicorn app:app \
                        --app-dir web --host 127.0.0.1 --port 8089 &
                    server_pid=$!
                    trap 'kill "$server_pid" 2>/dev/null || true' EXIT INT TERM

                    attempt=0
                    while [ "$attempt" -lt 30 ]; do
                        if "$VENV_DIR/bin/python" -c \
                            "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8089/api/scans?per_page=5', timeout=2)"; then
                            exit 0
                        fi
                        if ! kill -0 "$server_pid" 2>/dev/null; then
                            wait "$server_pid"
                            exit 1
                        fi
                        attempt=$((attempt + 1))
                        sleep 1
                    done

                    echo "Application did not become ready in time" >&2
                    exit 1
                '''
            }
        }

        stage('Build image') {
            steps {
                sh 'docker build --tag "$LOCAL_IMAGE" .'
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

        stage('Publish image') {
            when {
                expression {
                    params.PUBLISH_IMAGE &&
                        (env.BRANCH_NAME in ['main', 'master'] || env.TAG_NAME)
                }
            }
            steps {
                withCredentials([
                    usernamePassword(
                        credentialsId: params.DOCKER_CREDENTIALS_ID,
                        usernameVariable: 'REGISTRY_USERNAME',
                        passwordVariable: 'REGISTRY_PASSWORD'
                    )
                ]) {
                    sh '''
                        set -eu
                        registry=${DOCKER_REGISTRY#https://}
                        registry=${registry#http://}
                        registry=${registry%/}
                        printf '%s' "$REGISTRY_PASSWORD" | \
                            docker login "$registry" --username "$REGISTRY_USERNAME" --password-stdin

                        commit_tag=$(git rev-parse --short=12 HEAD)
                        docker tag "$LOCAL_IMAGE" "$DOCKER_IMAGE:$commit_tag"
                        docker push "$DOCKER_IMAGE:$commit_tag"

                        if [ -n "${TAG_NAME:-}" ]; then
                            safe_tag=$(printf '%s' "$TAG_NAME" | tr '/:@ ' '----')
                            docker tag "$LOCAL_IMAGE" "$DOCKER_IMAGE:$safe_tag"
                            docker push "$DOCKER_IMAGE:$safe_tag"
                        else
                            docker tag "$LOCAL_IMAGE" "$DOCKER_IMAGE:latest"
                            docker push "$DOCKER_IMAGE:latest"
                        fi
                    '''
                }
            }
        }
    }

    post {
        always {
            sh 'docker rm --force --volumes "$CONTAINER_NAME" >/dev/null 2>&1 || true'
        }
        cleanup {
            sh 'rm -rf "$VENV_DIR"'
        }
    }
}
