pipeline {
  agent any
  environment {
    IMAGE_NAME = 'trivy-scan'
    HARBOR_HOST = 'harbor.hoangvu75.space'
    HARBOR_PROJECT = 'library'
    MANIFEST_REPO = 'https://github.com/Hoangvu75/k8s_manifest.git'
    VALUES_PATH = 'apps/playground/trivy-scan/chart/values.yaml'
  }
  options {
    buildDiscarder(logRotator(numToKeepStr: '5'))
  }
  stages {
    stage('Build & Code Scan') {
      parallel {
        stage('Build') {
          steps {
            script {
              env.IMAGE_TAG = env.GIT_COMMIT?.take(7) ?: 'latest'
              podTemplate(containers: [
                containerTemplate(name: 'kaniko', image: 'gcr.io/kaniko-project/executor:v1.23.0-debug', command: 'sleep', args: '99d', ttyEnabled: true)
              ]) {
                node(POD_LABEL) {
                  checkout scm
                  container('kaniko') {
                    sh """
                      /kaniko/executor -f \${WORKSPACE}/Dockerfile -c \${WORKSPACE} \
                        --tarPath=\${WORKSPACE}/image.tar --no-push
                    """
                  }
                  stash name: 'image-tar', includes: 'image.tar'
                }
              }
            }
          }
        }
        stage('Trivy FS (Code)') {
          steps {
            script {
              podTemplate(containers: [
                containerTemplate(name: 'trivy', image: 'aquasec/trivy:latest', command: 'sleep', args: '99d', ttyEnabled: true)
              ]) {
                node(POD_LABEL) {
                  checkout scm
                  container('trivy') {
                    sh """
                      trivy fs --no-progress --exit-code 0 . 2>&1 | tee trivy-fs-full.log
                      awk '
                        / \\(npm\\)\$| \\(node-pkg\\)\$| \\(alpine\\)\$| \\(python\\)\$/ {p=1}
                        /^=+\$/ {if(p) print; next}
                        /^Total: [0-9]+ \\(UNKNOWN:/ {p=1}
                        p {print}
                        /^For OSS Maintainers|^To disable this notice|^Legend:/ {p=0}
                      ' trivy-fs-full.log > trivy-fs-summary.txt
                    """
                  }
                  stash name: 'trivy-fs-summary', includes: 'trivy-fs-summary.txt', allowEmpty: true
                }
              }
            }
          }
        }
      }
    }
    stage('Deploy & Image Scan') {
      parallel {
        stage('Push image & update manifest') {
          steps {
            script {
              def imageFull = "${env.HARBOR_HOST}/${env.HARBOR_PROJECT}/${env.IMAGE_NAME}:${env.IMAGE_TAG}"
              podTemplate(containers: [
                containerTemplate(name: 'skopeo', image: 'quay.io/skopeo/stable:latest', command: 'sleep', args: '99d', ttyEnabled: true)
              ]) {
                node(POD_LABEL) {
                  unstash 'image-tar'
                  withCredentials([usernamePassword(credentialsId: 'harbor-credentials', usernameVariable: 'HARBOR_USER', passwordVariable: 'HARBOR_PASS')]) {
                    container('skopeo') {
                      sh """
                        skopeo copy --dest-creds="\${HARBOR_USER}:\${HARBOR_PASS}" \
                          docker-archive:\${WORKSPACE}/image.tar docker://${imageFull}
                      """
                    }
                  }
                  withCredentials([usernamePassword(credentialsId: 'github-credentials', usernameVariable: 'GIT_USER', passwordVariable: 'GIT_TOKEN')]) {
                    sh """
                      rm -rf k8s_manifest || true
                      REPO_URL=\$(echo "${env.MANIFEST_REPO}" | sed "s|https://|https://\\${GIT_USER}:\\${GIT_TOKEN}@|")
                      git clone \$REPO_URL k8s_manifest
                      cd k8s_manifest
                      sed -i 's/tag: ".*"/tag: "${env.IMAGE_TAG}"/' ${env.VALUES_PATH}
                      git config user.email "jenkins@ci.local"
                      git config user.name "Jenkins CI"
                      git add ${env.VALUES_PATH}
                      git commit -m "chore: update ${env.IMAGE_NAME} image tag to ${env.IMAGE_TAG}" || echo "No changes to commit"
                      git push origin master
                    """
                  }
                  withCredentials([usernamePassword(credentialsId: 'harbor-credentials', usernameVariable: 'HARBOR_USER', passwordVariable: 'HARBOR_PASS')]) {
                    sh '''
                      KEEP_COUNT=2
                      API_URL="https://${HARBOR_HOST}/api/v2.0/projects/${HARBOR_PROJECT}/repositories/${IMAGE_NAME}/artifacts"
                      RESPONSE=$(curl -s -u "${HARBOR_USER}:${HARBOR_PASS}" "${API_URL}?page_size=100&sort=-push_time")
                      ARTIFACTS=$(echo "$RESPONSE" | grep -o '"digest":"sha256:[^"]*"' | sed 's/"digest":"//g' | sed 's/"//g')
                      COUNT=0
                      for DIGEST in $ARTIFACTS; do
                        COUNT=$((COUNT + 1))
                        if [ $COUNT -gt $KEEP_COUNT ]; then
                          echo "Deleting old artifact: $DIGEST"
                          curl -s -X DELETE -u "${HARBOR_USER}:${HARBOR_PASS}" "${API_URL}/${DIGEST}" || true
                        fi
                      done
                      echo "Cleanup complete. Kept $KEEP_COUNT most recent images."
                    '''
                  }
                }
              }
            }
          }
        }
        stage('Trivy Image') {
          steps {
            script {
              podTemplate(containers: [
                containerTemplate(name: 'trivy', image: 'aquasec/trivy:latest', command: 'sleep', args: '99d', ttyEnabled: true)
              ]) {
                node(POD_LABEL) {
                  unstash 'image-tar'
                  container('trivy') {
                    sh """
                      trivy image --no-progress --exit-code 0 --input \${WORKSPACE}/image.tar 2>&1 | tee trivy-image-full.log
                      awk '
                        / \\(npm\\)\$| \\(node-pkg\\)\$| \\(alpine\\)\$/ {p=1}
                        /^=+\$/ {if(p) print; next}
                        /^Total: [0-9]+ \\(UNKNOWN:/ {p=1}
                        p {print}
                        /^For OSS Maintainers|^To disable this notice|^Legend:/ {p=0}
                      ' trivy-image-full.log > trivy-image-summary.txt
                    """
                  }
                  stash name: 'trivy-image-summary', includes: 'trivy-image-summary.txt', allowEmpty: true
                }
              }
            }
          }
        }
      }
    }
  }
  post {
    always {
      script {
        def trivyFs = 'N/A'
        def trivyImage = 'N/A'
        try { unstash 'trivy-fs-summary'; trivyFs = readFile('trivy-fs-summary.txt') } catch (e) { /* ignore */ }
        try { unstash 'trivy-image-summary'; trivyImage = readFile('trivy-image-summary.txt') } catch (e) { /* ignore */ }
        def payload = groovy.json.JsonOutput.toJson([
          job_name: env.JOB_NAME,
          build_number: env.BUILD_NUMBER,
          build_url: env.BUILD_URL,
          status: currentBuild.currentResult,
          trivy_fs_summary: trivyFs,
          trivy_image_summary: trivyImage
        ])
        writeFile file: 'webhook-payload.json', text: payload
        sh 'curl -X POST "https://n8n.hoangvu75.space/webhook/jenkins-notify" -H "Content-Type: application/json" -d @webhook-payload.json'
      }
    }
  }
}
