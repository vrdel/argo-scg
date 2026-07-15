pipeline {
    agent any
    options {
        checkoutToSubdirectory('argo-scg')
    }
    environment {
        PROJECT_DIR="argo-scg"
        GIT_COMMIT=sh(script: "cd ${WORKSPACE}/$PROJECT_DIR && git log -1 --format=\"%H\"",returnStdout: true).trim()
        GIT_COMMIT_HASH=sh(script: "cd ${WORKSPACE}/$PROJECT_DIR && git log -1 --format=\"%H\" | cut -c1-7",returnStdout: true).trim()
        GIT_COMMIT_DATE=sh(script: "date -d \"\$(cd ${WORKSPACE}/$PROJECT_DIR && git show -s --format=%ci ${GIT_COMMIT_HASH})\" \"+%Y%m%d%H%M%S\"",returnStdout: true).trim()

    }
    stages {
        stage ('Building and testing...') {
            agent {
                docker {
                    image 'argo.registry:5000/epel-9-ams'
                    alwaysPull true
                    args '-u jenkins:jenkins'
                }
            }
            stages {
                stage ('Test Rocky 9') {
                    steps {
                        echo 'Executing unit tests @ Rocky 9...'
                        sh '''
                            cd $WORKSPACE/$PROJECT_DIR/
                            rm -f tests/argo_scg
                            ln -s $PWD/modules/ tests/argo_scg
                            coverage run -m xmlrunner discover --output-file junit.xml -v tests/
                            coverage xml
                        '''
						recordCoverage(
							tools: [
								[parser: 'COBERTURA', pattern: '**/coverage.xml'],
								[parser: 'JUNIT', pattern: '**/junit.xml']
							]
						)

                    }
                }
                stage ('Build Rocky 9 RPM') {
                    steps {
                        echo 'Building Rocky 9 RPM...'
                        withCredentials(bindings: [sshUserPrivateKey(credentialsId: 'jenkins-rpm-repo', usernameVariable: 'REPOUSER', \
                                                                    keyFileVariable: 'REPOKEY')]) {
                            sh "/home/jenkins/build-rpm.sh -w ${WORKSPACE} -b ${BRANCH_NAME} -d rocky9 -p ${PROJECT_DIR} -s ${REPOKEY}"
                        }
                        archiveArtifacts artifacts: '**/*.rpm', fingerprint: true
                    }
                }
            }
        }
    }
    post {
        always {
            cleanWs()
        }
        success {
            script{
                if ( env.BRANCH_NAME == 'master' || env.BRANCH_NAME == 'devel' ) {
                    slackSend( message: ":rocket: New version for <$BUILD_URL|$PROJECT_DIR>:$BRANCH_NAME Job: $JOB_NAME !")
                }
            }
        }
        failure {
            script{
                if ( env.BRANCH_NAME == 'master' || env.BRANCH_NAME == 'devel' ) {
                    slackSend( message: ":rain_cloud: Build Failed for <$BUILD_URL|$PROJECT_DIR>:$BRANCH_NAME Job: $JOB_NAME")
                }
            }
        }
    }
}
