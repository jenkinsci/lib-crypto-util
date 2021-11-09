  
/* Only keep the 10 most recent builds. */
properties([[$class: 'BuildDiscarderProperty',
                strategy: [$class: 'LogRotator', numToKeepStr: '10']]])

// TODO: Move it to Jenkins Pipeline Library

/* These platforms correspond to labels in ci.jenkins.io, see:
 *  https://github.com/jenkins-infra/documentation/blob/master/ci.adoc
 */
List platforms = ['linux', 'windows']
Map branches = [:]

for (int i = 0; i < platforms.size(); ++i) {
    String label = platforms[i]
    branches[label] = {
        node(label) {
            timestamps {
                stage('Checkout') {
                    checkout scm
                }

                stage('Build') {
                    timeout(30) {
                      infra.runMaven(["clean", "install", "-Dmaven.test.failure.ignore=true", "-Dspotbugs.failOnError=false"])
                    }
                }

                stage('Archive') {
                    /* Archive the test results */
                    junit '**/target/surefire-reports/TEST-*.xml'

                    if (label == 'linux') {
                      archiveArtifacts artifacts: 'target/**/*.jar'
                      def folders = env.JOB_NAME.split('/')
                      if (folders.length > 1) {
                        discoverGitReferenceBuild(scm: folders[1])
                      }
                      recordIssues([tool: spotBugs(pattern: '**/target/spotbugsXml.xml,**/target/findbugsXml.xml'),
                          sourceCodeEncoding: 'UTF-8',
                          skipBlames: true,
                          trendChartType: 'TOOLS_ONLY',
                          qualityGates: [[threshold: 1, type: 'NEW', unstable: true]]])
                    }
                }
            }
        }
    }
}

/* Execute our platforms in parallel */
parallel(branches)
