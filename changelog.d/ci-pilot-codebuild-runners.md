- **Most CI jobs now run on AWS CodeBuild-hosted runners** (#735). `guard`, `pinned-demo`, the
  install, bind, drift, health, alert and verdict jobs use the `gha-open-fleet` CodeBuild project
  in us-east-1. `tests`, `floor`, `checks`, `gates` and the vf-bench jobs stay GitHub-hosted
  (they need a non-root runner), as do Docker Hub pulls and the release publishers.
  [ops](../docs/ops.md#ci-runners) lists the AWS prerequisites, how a fork switches back to
  `ubuntu-latest`, and what a job stuck in "Queued" means.
