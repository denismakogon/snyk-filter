#!/bin/bash
set -ex

# ensure working dir is clean
git status
if [[ -z $(git status -s) ]]
then
  echo "tree is clean"
else
  echo "tree is dirty, please commit changes before running this"
  exit 1
fi

version_file="config/version.go"
# Bump version, patch by default - also checks if previous commit message contains `[bump X]`, and if so, bumps the appropriate semver number - https://github.com/treeder/dockers/tree/master/bump
docker run --rm -it -v $PWD:/app -w /app treeder/bump --filename $version_file "$(git log -1 --pretty=%B)"
version=$(grep -m1 -Eo "[0-9]+\.[0-9]+\.[0-9]+" $version_file)
echo "Version: $version"

make release

tag="$version"
git add -u
git commit -m "Snyk filter: $version release [skip ci]"
git tag -f -a $tag -m "version $version"
git push
git push -q origin $tag

docker build -t denismakogon/snyk-filter:$tag .
docker push denismakogon/snyk-filter:$tag
