## Overview
<!-- Provide a concise summary of the changes and the problem they solve. -->

## Changes Proposed
* 
* 

## Related Issue(s)
<!-- Fixes #issue_number or References #issue_number -->

## Checklist
- [ ] Code strictly formatted using `gofmt -w .`
- [ ] Static analysis passes (`go vet ./...`)
- [ ] Security vulnerability scan passes (`govulncheck ./...`)
- [ ] Non-root unit tests pass (`go test -v -race ./pkg/...`)
- [ ] Root integration tests pass (`sudo -E env "PATH=$PATH" go test -v ./pkg/sandbox/...`)
- [ ] Commits adhere to Conventional Commits format (`type(scope): description`)
- [ ] Commit is signed (`git commit -s`)