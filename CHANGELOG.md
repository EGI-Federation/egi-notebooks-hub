<!-- markdownlint-disable MD024 -->

# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.3.0] - 2024-11-27

### Added

- Conditionally mount secrets in user environmet
  [#145](https://github.com/EGI-Federation/egi-notebooks-hub/pull/145),
  [#150](https://github.com/EGI-Federation/egi-notebooks-hub/pull/150),
  [#151](https://github.com/EGI-Federation/egi-notebooks-hub/pull/151)

- Support service accounts without username claim
  [#140](https://github.com/EGI-Federation/egi-notebooks-hub/pull/140)

- Add timeout to Hub API calls from JWT wrapper
  [#139](https://github.com/EGI-Federation/egi-notebooks-hub/pull/139)

### Changed

- Update Zero2Jupyter to 4.0.0 (with associated dependencies) and update
  templates to work with JupyterHub 5.x
  [#141](https://github.com/EGI-Federation/egi-notebooks-hub/pull/141),
  [#142](https://github.com/EGI-Federation/egi-notebooks-hub/pull/142),
  [#143](https://github.com/EGI-Federation/egi-notebooks-hub/pull/143),
  [#146](https://github.com/EGI-Federation/egi-notebooks-hub/pull/146),
  [#149](https://github.com/EGI-Federation/egi-notebooks-hub/pull/149)

- Use introspection endpoint for JWT authentication
  [#138](https://github.com/EGI-Federation/egi-notebooks-hub/pull/138)

## [0.2.0] - 2024-10-02

### Added

- Better templates
  [#101](https://github.com/EGI-Federation/egi-notebooks-hub/pull/101)
- D4Science: filter profiles depending on the server name
  [#105](https://github.com/EGI-Federation/egi-notebooks-hub/pull/105)
- D4Science: Support data manager role for volumes
  [#106](https://github.com/EGI-Federation/egi-notebooks-hub/pull/106)
- D4Science: set CPU guarantee depending on limit
  [#107](https://github.com/EGI-Federation/egi-notebooks-hub/pull/107)
- D4Science: support Ophidia
  [#115](https://github.com/EGI-Federation/egi-notebooks-hub/pull/115)
- Support for JWT authentication and proxy service
  [#119](https://github.com/EGI-Federation/egi-notebooks-hub/pull/119),
  [#122](https://github.com/EGI-Federation/egi-notebooks-hub/pull/122),
  [#123](https://github.com/EGI-Federation/egi-notebooks-hub/pull/123),
  [#127](https://github.com/EGI-Federation/egi-notebooks-hub/pull/127),
  [#135](https://github.com/EGI-Federation/egi-notebooks-hub/pull/135)
- Add version to the package
  [#124](https://github.com/EGI-Federation/egi-notebooks-hub/pull/124)
- EOSC Node AAI support
  [#121](https://github.com/EGI-Federation/egi-notebooks-hub/pull/121)
- D4Science: support for GKE deployment
  [#117](https://github.com/EGI-Federation/egi-notebooks-hub/pull/117)
- EC Templates
  [#131](https://github.com/EGI-Federation/egi-notebooks-hub/pull/131),
  [#132](https://github.com/EGI-Federation/egi-notebooks-hub/pull/132),
  [#133](https://github.com/EGI-Federation/egi-notebooks-hub/pull/133),
  [#134](https://github.com/EGI-Federation/egi-notebooks-hub/pull/134)
- Support anonymous users from AAI
  [#136](https://github.com/EGI-Federation/egi-notebooks-hub/pull/136)
- Configurable leeway time for token refresh
  [#137](https://github.com/EGI-Federation/egi-notebooks-hub/pull/137)

### Changed

- Update GitHub Actions dependencies
  [#104](https://github.com/EGI-Federation/egi-notebooks-hub/pull/104),
  [#110](https://github.com/EGI-Federation/egi-notebooks-hub/pull/110),
  [#111](https://github.com/EGI-Federation/egi-notebooks-hub/pull/111),
  [#112](https://github.com/EGI-Federation/egi-notebooks-hub/pull/112),
  [#109](https://github.com/EGI-Federation/egi-notebooks-hub/pull/109),
  [#113](https://github.com/EGI-Federation/egi-notebooks-hub/pull/113),
  [#114](https://github.com/EGI-Federation/egi-notebooks-hub/pull/114),
  [#120](https://github.com/EGI-Federation/egi-notebooks-hub/pull/120),
  [#118](https://github.com/EGI-Federation/egi-notebooks-hub/pull/118),
  [#129](https://github.com/EGI-Federation/egi-notebooks-hub/pull/129)
- Upgrade dependencies k8s-hub (3.2.1), jupyterhub (4.0.2),
  oauthenticator(16.1.0), kubespawner(6.1.0)
- Add new dependencies: fastapi, pydantic-settings, pbr
- Update to Changelog 1.1.0

### Fixed

- Secret handling for tokens
  [#103](https://github.com/EGI-Federation/egi-notebooks-hub/pull/103)
- D4Science: pick roles from the right token
  [#108](https://github.com/EGI-Federation/egi-notebooks-hub/pull/108)
- Do not try to refresh non Check-in users
  [#116](https://github.com/EGI-Federation/egi-notebooks-hub/pull/116)
- Fix profile filter
  [#125](https://github.com/EGI-Federation/egi-notebooks-hub/pull/125)

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
