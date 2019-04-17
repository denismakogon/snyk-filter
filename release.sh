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

git pull

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
git push -q https://${GH_TOKEN}@github.com/denismakogon/snyk-filter
git push -q https://${GH_TOKEN}@github.com/denismakogon/snyk-filter origin $tag

# For GitHub
url='https://api.github.com/repos/denismakogon/snyk-filter/releases'
output=$(curl -s -u $GH_DEPLOY_USER:$GH_DEPLOY_KEY -d "{\"tag_name\": \"$version\", \"name\": \"$version\"}" $url)
upload_url=$(echo "$output" | python -c 'import json,sys;obj=json.load(sys.stdin);print obj["upload_url"]' | sed -E "s/\{.*//")
html_url=$(echo "$output" | python -c 'import json,sys;obj=json.load(sys.stdin);print obj["html_url"]')
curl --data-binary "@snyk-filter_linux"  -H "Content-Type: application/octet-stream" -u $GH_DEPLOY_USER:$GH_DEPLOY_KEY $upload_url\?name\=snyk-filter_linux >/dev/null
curl --data-binary "@snyk-filter_mac"    -H "Content-Type: application/octet-stream" -u $GH_DEPLOY_USER:$GH_DEPLOY_KEY $upload_url\?name\=snyk-filter_mac >/dev/null
