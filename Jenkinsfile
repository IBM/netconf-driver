#!/usr/bin/env groovy

String tarquinBranch = "CPNA-1619"

library "tarquin@$tarquinBranch"

pipelinePy {
  pkgInfoPath = 'netconfdriver/pkg_info.json'
  applicationName = 'netconf-driver'
  releaseArtifactsPath = 'release-artifacts'
  attachDocsToRelease = true
  attachHelmToRelease = true
}
