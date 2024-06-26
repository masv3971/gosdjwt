.PHONY: update clean build build-all run package deploy test authors dist check-tag

NAME 					:= gosdjwt
TAGS					:= $(shell git tag)
VERSION					:= $(shell tail -1 RELEASE.txt|awk -F" : " '{print $$1}')
COMMIT_MSG				:= $(shell tail -1 RELEASE.txt|awk -F" : " '{print $$2}')

default: release-patch

release-patch: check-tag check-files tidy test add commit release-tag push-tag push-main go-list
		$(info relese ${NAME}@${VERSION})

tidy:
	$(info tidy up..)
	go mod tidy

test:
	$(info test ${NAME})
	go test -v --cover .

gosec:                                                                                                                                                                                                                                         
	$(info Run gosec)                                                                                                                                                                                                                      
	gosec -color -nosec -tests ./...                                                                                                                                                                                                       
                                                                                                                                                                                                                                               
staticcheck:                                                                                                                                                                                                                                   
	$(info Run staticcheck)                                                                                                                                                                                                                
	staticcheck ./...   

git-status:
	$(info files to be added:)
	@git status
	$(read -p "Press enter in order to precede")

add: git-status
	git add .

commit:
ifndef COMMIT_MSG
	$(error No commit message found)
endif
		git commit -S -m"${NAME} release $(VERSION): $(COMMIT_MSG)"

release-tag:
		git tag ${VERSION}

push-tag:
		git push origin ${VERSION}

push-main:
		git push origin main

check-tag:
ifndef VERSION
	$(error version is empty)
endif

	git fetch --tags
ifeq ($(filter $(TAGS), $(VERSION)) ,$(VERSION))
	$(error $(VERSION) is already used, make other one please)
endif

go-list:	
		GOPROXY=proxy.golang.org go list -m github.com/masv3971/${NAME}@${VERSION}

check-files: check-release-file check-license-file check-readme-file

check-release-file:
ifeq (,$(wildcard ./RELEASE.txt))
	$(error RELEASE.txt file does not exists, make it!)
endif

check-license-file:
ifeq (,$(wildcard ./LICENSE.md))
	$(error LICENSE.md file does not exists, make it!)
endif

check-readme-file:
ifeq (,$(wildcard ./README.md))
	$(error README file does not exists, make it!)
endif

vscode:
	$(info Install APT packages)
	sudo apt-get update && sudo apt-get install -y \
		protobuf-compiler \
		netcat-openbsd
	$(info Install go packages)
	go install golang.org/x/tools/cmd/deadcode@latest
	go install github.com/securego/gosec/v2/cmd/gosec@latest
	go install honnef.co/go/tools/cmd/staticcheck@latest