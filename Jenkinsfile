pipeline {
    agent any

    environment {
        PATH = "C:\\Program Files\\mingw64\\bin;" +
               "C:\\Python\\Python311\\;" +
               "C:\\Python\\Python311\\Scripts;" +
               "C:\\Program Files\\Cppcheck;" +
               "${env.PATH}"
    }

    options {
        skipDefaultCheckout true
    }

    stages {
        stage('Set Variables') {
            steps {
                script {
                    env.DUMP1090_DIR = "dump1090"
                    env.RUI_DIR = "RUI"
                    env.DUMP1090_REPO = "https://github.com/LGSDET/SDET_JETLAG_PHASE2_dump1090.git"
                    env.DUMP1090_BRANCH = "master"
                    env.RUI_REPO = "https://github.com/LGSDET/SDET_JETLAG_PHASE2_RUI.git"
                    env.RUI_BRANCH = "master"
                }
            }
        }

        stage('Checkout dump1090') {
            steps {
                dir("${env.DUMP1090_DIR}") {
                    git credentialsId: 'github-https-token',
                        url: "${env.DUMP1090_REPO}",
                        branch: "${env.DUMP1090_BRANCH}"
                }
            }
        }

        stage('Cppcheck dump1090') {
            steps {
                dir("${env.DUMP1090_DIR}") {
                    catchError(buildResult: 'SUCCESS', stageResult: 'UNSTABLE') {
                        bat """
                        if exist cppcheck_report rmdir /s /q cppcheck_report
                        mkdir cppcheck_report

                        cppcheck --enable=all --inconclusive --std=c99 --language=c --xml --xml-version=2 --relative-paths=. ^
                            dump1090.c 2> cppcheck_report\\cppcheck.xml
                        
                        python "C:\\Program Files\\Cppcheck\\htmlreport\\cppcheck-htmlreport.py" --file=cppcheck_report\\cppcheck.xml --report-dir=cppcheck_report
                        """
                    }
                    script {
                        def xmlContent = readFile('cppcheck_report/cppcheck.xml')
                        if (!xmlContent.trim().startsWith('<?xml')) {
                            error("cppcheck.xml is not a valid XML file. Actual content:\\n${xmlContent.take(200)}")
                        }
                    }
                    recordIssues tools: [cppCheck(pattern: 'cppcheck_report/cppcheck.xml')], id: 'dump1090', name: 'CPPCheck Warnings (dump1090)', skipBlames: true
                }
            }
        }

        stage('Publish dump1090 Cppcheck Report') {
            steps {
                dir("${env.DUMP1090_DIR}") {
                    publishHTML([
                        reportDir: "cppcheck_report",
                        reportFiles: 'index.html',
                        reportName: 'Cppcheck Report (dump1090)',
                        keepAll: true,
                        alwaysLinkToLastBuild: true,
                        allowMissing: true
                    ])
                }
            }
        }

        /*
        stage('Checkout RUI.git') {
            steps {
                dir("${env.RUI_DIR}") {
                    git credentialsId: 'github-https-token',
                        url: "${env.RUI_REPO}",
                        branch: "${env.RUI_BRANCH}"
                }
            }
        }
        */

        stage('Cppcheck RUI.git') {
            steps {
                dir("${env.RUI_DIR}") {
                    catchError(buildResult: 'SUCCESS', stageResult: 'UNSTABLE') {
                        bat """
                        if exist cppcheck_report rmdir /s /q cppcheck_report
                        mkdir cppcheck_report
        
                        setlocal enabledelayedexpansion
                        set SRCFILES=
                        for %%f in (*.cpp *.h) do (
                            echo %%f | findstr /i /c:"Components\\" >nul
                            if errorlevel 1 (
                                set SRCFILES=!SRCFILES! %%f
                            )
                        )
        
                        echo ==== [List of .cpp/.h files in the current folder] ====
                        echo !SRCFILES!
                        echo =======================================
        
                        cppcheck --enable=all --inconclusive --std=c++17 --language=c++ --xml --xml-version=2 --relative-paths=. ^
                            -i Components ^
                            !SRCFILES! 2> cppcheck_report\\cppcheck.xml
                            
                        python "C:\\Program Files\\Cppcheck\\htmlreport\\cppcheck-htmlreport.py" --file=cppcheck_report\\cppcheck.xml --report-dir=cppcheck_report
                        endlocal
                        """
                    }
                    script {
                        def xmlContent = readFile('cppcheck_report/cppcheck.xml')
                        if (!xmlContent.trim().startsWith('<?xml')) {
                            error("cppcheck.xml is not a valid XML file. Actual content:\\n${xmlContent.take(200)}")
                        }
                    }
                    recordIssues tools: [cppCheck(pattern: 'cppcheck_report/cppcheck.xml')], id: 'rui', name: 'CPPCheck Warnings (RUI)', skipBlames: true
                }
            }
        }

        stage('Publish RUI.git Cppcheck Report') {
            steps {
                dir("${env.RUI_DIR}") {
                    publishHTML([
                        reportDir: "cppcheck_report",
                        reportFiles: 'index.html',
                        reportName: 'Cppcheck Report (RUI.git)',
                        keepAll: true,
                        alwaysLinkToLastBuild: true,
                        allowMissing: true
                    ])
                }
            }
        }
    }

    post {
        always {
            archiveArtifacts artifacts: "${env.DUMP1090_DIR}/cppcheck_report/**/*", allowEmptyArchive: true
            archiveArtifacts artifacts: "${env.RUI_DIR}/cppcheck_report/**/*", allowEmptyArchive: true
        }
    }
}
