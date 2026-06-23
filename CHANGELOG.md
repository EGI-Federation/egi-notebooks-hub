<!-- markdownlint-disable MD024 -->

# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.0.0] - 2026-06-23

### Added

- Share manager and token acquirer extension
  [#186](https://github.com/EGI-Federation/egi-notebooks-hub/pull/186),
  [#174](https://github.com/EGI-Federation/egi-notebooks-hub/pull/174),
  [#171](https://github.com/EGI-Federation/egi-notebooks-hub/pull/171),
  [#164](https://github.com/EGI-Federation/egi-notebooks-hub/pull/164),
  [#169](https://github.com/EGI-Federation/egi-notebooks-hub/pull/169),
  [#179](https://github.com/EGI-Federation/egi-notebooks-hub/pull/179)
- Unit and integration tests EGI hub
  [#197](https://github.com/EGI-Federation/egi-notebooks-hub/pull/197)
- Allow setting the name of the service
  [#184](https://github.com/EGI-Federation/egi-notebooks-hub/pull/184)
- Adding light dark mode switch styling
  [#166](https://github.com/EGI-Federation/egi-notebooks-hub/pull/166),
  [#167](https://github.com/EGI-Federation/egi-notebooks-hub/pull/167),
  [#168](https://github.com/EGI-Federation/egi-notebooks-hub/pull/168),
- Make the mounting of secrets configurable from profiles
  [#163](https://github.com/EGI-Federation/egi-notebooks-hub/pull/163),
  [#170](https://github.com/EGI-Federation/egi-notebooks-hub/pull/170),
  [#172](https://github.com/EGI-Federation/egi-notebooks-hub/pull/172)
- Adding accept share template into EGI templates
  [#165](https://github.com/EGI-Federation/egi-notebooks-hub/pull/165)
- Dynamic load of EOSC templates
  [#178](https://github.com/EGI-Federation/egi-notebooks-hub/pull/178)

### Changed

- Switching to IdP primary group ordering
  [#200](https://github.com/EGI-Federation/egi-notebooks-hub/pull/200)

### Fixed

- Better detect issues with refresh exchange
  [#157](https://github.com/EGI-Federation/egi-notebooks-hub/pull/157)
- Moving load_user_options into pre_spawn_hook
  [#158](https://github.com/EGI-Federation/egi-notebooks-hub/pull/158)
- Fixing text centering in EOSC error templates
  [#185](https://github.com/EGI-Federation/egi-notebooks-hub/pull/185)
- Adapt style of EGI Notebooks to newer Jupyterhub
  [#159](https://github.com/EGI-Federation/egi-notebooks-hub/pull/159)
- Fixing templates
  [#175](https://github.com/EGI-Federation/egi-notebooks-hub/pull/175),
  [#176](https://github.com/EGI-Federation/egi-notebooks-hub/pull/176),
  [#161](https://github.com/EGI-Federation/egi-notebooks-hub/pull/161)
- Update GGUS URL
  [#160](https://github.com/EGI-Federation/egi-notebooks-hub/pull/160)
- Ensure volumes is a list
  [#177](https://github.com/EGI-Federation/egi-notebooks-hub/pull/177)
- Improve support for binder
  [#180](https://github.com/EGI-Federation/egi-notebooks-hub/pull/180)

### Removed

- Remove D4Science code
  [#152](https://github.com/EGI-Federation/egi-notebooks-hub/pull/152)

### Chore

- Introduce dependabot updates for python packages
  [#154](https://github.com/EGI-Federation/egi-notebooks-hub/pull/154)
- Update ECL to 4.10.0
  [#153](https://github.com/EGI-Federation/egi-notebooks-hub/pull/153),
  [#155](https://github.com/EGI-Federation/egi-notebooks-hub/pull/155)
- JupyterHub and related dependencies upgrades
  [#156](https://github.com/EGI-Federation/egi-notebooks-hub/pull/156),
  [#173](https://github.com/EGI-Federation/egi-notebooks-hub/pull/173),
  [#196](https://github.com/EGI-Federation/egi-notebooks-hub/pull/196),
  [#194](https://github.com/EGI-Federation/egi-notebooks-hub/pull/194),
  [#195](https://github.com/EGI-Federation/egi-notebooks-hub/pull/195),
  [#198](https://github.com/EGI-Federation/egi-notebooks-hub/pull/198),
  [#199](https://github.com/EGI-Federation/egi-notebooks-hub/pull/199),
  [#203](https://github.com/EGI-Federation/egi-notebooks-hub/pull/203),
  [#204](https://github.com/EGI-Federation/egi-notebooks-hub/pull/204)
- Build dependencies upgrades
  [#162](https://github.com/EGI-Federation/egi-notebooks-hub/pull/162),
  [#181](https://github.com/EGI-Federation/egi-notebooks-hub/pull/181),
  [#187](https://github.com/EGI-Federation/egi-notebooks-hub/pull/187),
  [#188](https://github.com/EGI-Federation/egi-notebooks-hub/pull/188),
  [#190](https://github.com/EGI-Federation/egi-notebooks-hub/pull/190),
  [#191](https://github.com/EGI-Federation/egi-notebooks-hub/pull/191),
  [#192](https://github.com/EGI-Federation/egi-notebooks-hub/pull/192),
  [#201](https://github.com/EGI-Federation/egi-notebooks-hub/pull/201),
  [#202](https://github.com/EGI-Federation/egi-notebooks-hub/pull/202),
  [#213](https://github.com/EGI-Federation/egi-notebooks-hub/pull/213),
  [#214](https://github.com/EGI-Federation/egi-notebooks-hub/pull/214),
  [#215](https://github.com/EGI-Federation/egi-notebooks-hub/pull/215),
  [#216](https://github.com/EGI-Federation/egi-notebooks-hub/pull/216)

## New Contributors

- @nikl11 made their first contribution in
  [#197](https://github.com/EGI-Federation/egi-notebooks-hub/pull/197)

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
