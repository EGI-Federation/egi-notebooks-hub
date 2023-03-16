<!-- markdownlint-disable MD024 -->
# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- More flexible templates for the hub

### Fixed
- Fixed the update of the secret with the renewed access token
- Use "Privacy Notice" instead of "Privacy Policy"

## [0.1.0] - 2023-03-06

First tagged release

### Added

- EGICheckinAuthenticator for authentication with EGI Check-in
- EGISpawner expands Kubespawner to use Check-in information
- OnedataAuthenticator and OnedataSpawner adds onedata support on top of the
  EGICheckinAuthenticator and EGISpawner
- D4ScienceOauthenticator & D4ScienceSpawner for supporting the D4Science VREs
  with EGI Notebooks
- Welcome page for showing an intro page to users
- Custom templates for login and error pages
