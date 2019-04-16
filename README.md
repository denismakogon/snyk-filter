# Snyk-based Docker image security scanning

## Idea

[Snyk](https://snyk.io) by itself identifies a set of low/medium/high severity issues necessary to be addressed.

With some filtering it is possible to filter out a list of actual packages necessary to be update based on their severity.

## Install Snyk CLI tool

```bash
npm install -g snyk
snyk auth
```

## Purpose

Purpose of the tool to filter out only necessary portion of data out of the whole report from Snyk.

## Usage

Please see available options:
```bash
snyk-filter -h
Usage of snyk-filter:
  -severity string
        the severity to filter issues by, values: all/final/high/medium/low (default "all")
```

```bash
snyk test --docker fnproject/python:3.7.1-dev --json | \
  snyk-filter -severity final

-----------------------------------------
Final packages to update:
glibc/libc6-dev==2.24-11+deb9u4
glibc/libc-dev-bin==2.24-11+deb9u4
glibc/libc-bin==2.24-11+deb9u4
glibc/libc6==2.24-11+deb9u4
glibc/multiarch-support==2.24-11+deb9u4
openssl/libssl1.1==1.1.0j-1~deb9u1
openssl==1.1.0j-1~deb9u1
systemd/libsystemd0==232-25+deb9u7
systemd/libudev1==232-25+deb9u7
apt/libapt-pkg5.0==1.4.9
apt==1.4.9
-----------------------------------------
```

Severity "final" represents a set of OS packages necessary to be fixed within high, medium and low severities altogether.
