<div align="center" id="top"> 
  <img src="./.github/klortho.png" alt="Klortho" />
  &#xa0;
</div>

<h1 align="center">Klortho</h1>
<h3 align="center">An SSH client and server management utility built with Tauri and React.</h3>
&#xa0;
<p align="center">
  <img alt="Github top language" src="https://img.shields.io/github/languages/top/dainbrump/klortho?color=56BEB8">
  <img alt="Github language count" src="https://img.shields.io/github/languages/count/dainbrump/klortho?color=56BEB8">
  <img alt="Repository size" src="https://img.shields.io/github/repo-size/dainbrump/klortho?color=56BEB8">
  <img alt="License" src="https://img.shields.io/github/license/dainbrump/klortho?color=56BEB8">
  <img alt="Github issues" src="https://img.shields.io/github/issues/dainbrump/klortho?color=56BEB8" />
  <img alt="Github forks" src="https://img.shields.io/github/forks/dainbrump/klortho?color=56BEB8" />
  <img alt="Github stars" src="https://img.shields.io/github/stars/dainbrump/klortho?color=56BEB8" />
</p>

<h4 align="center"> 
	🚧  DO NOT USE!!! Still under active development.  🚧
</h4> 
<hr>

<p align="center">
  <a href="#dart-about">About</a> &#xa0; | &#xa0; 
  <a href="#sparkles-features">Features</a> &#xa0; | &#xa0;
  <a href="#rocket-technologies">Technologies</a> &#xa0; | &#xa0;
  <a href="#white_check_mark-requirements">Requirements</a> &#xa0; | &#xa0;
  <a href="#checkered_flag-starting">Starting</a> &#xa0; | &#xa0;
  <a href="#memo-license">License</a> &#xa0; | &#xa0;
  <a href="https://github.com/dainbrump" target="_blank">Author</a>
</p>

<br>

## :dart: About

First and foremost, this is 100% a personal project for me to learn more about Tauri and Rust. I am also learning more about React, TailwindCSS and ShadCN among many other things. This is a "stretch" project - something much bigger than the typical Todo App - for me to learn from. At the end of this, I do want to have a fully functional and useful desktop application that will work for my purposes at the very least. If it becomes something bigger, then cool. So use at your own risk or learn along with me.

Klortho is named after the "keymaster" character from the original Ghostbusters movie. It started as, and currently is, part experiment and part necessary tool. I spelled it with a "K" to 1) avoid copyright/trademark drama; and 2) I'm a KDE user and we always name things starting with "K". (I use Arch, btw)

There are many tutorials and other tools to assist users with managing ssh server configurations and client configurations. I've used them all and like them just fine. In my previous job and in my personal life, I manage a lot more servers, EC2 instances, Raspberry Pis, etc than I probably should. As a result, my `.ssh` directory gets quite messy and sometimes out of date. Then it becomes an ordeal to clean up settings and make sure everything still works. While I have no problems using a command line editor to make the changes, I've gotten kind of lazy about such maintenance tasks in my old-age and prefer a simple GUI for things like this. Plus, I've spent the past 20+ years working in web application development and wanted to try my hand at something a little bit different. Thus, Klortho was born.

The goals for Klortho are:

- Provide a simple UI for managing the configuration of my ssh client connections.
- Provide a simple UI for managing sshd server configurations that can be saved and copied to machines as needed.
- Provide a simple UI for "organizing" all of my public/private keys that I need for ssh to work.

## :sparkles: Features

There are no currently finished / usable features at the moment. Klortho is very much a work in progress. Here is a list of features / functions that are currently in progress or completed.

1. Manage SSH Client Configurations

- [ ] Load existing configurations
  - [x] Support "Include" statements when parsing the configurations.
  - [x] Support most, if not all, SSH client configuration options.
  - [?] Organize Host blocks by sensible groupings. I.e., group all Host blocks by file, sort them in order as rules _could_ cascade from one Host block into another.
  - [ ] When an "Include" is parsed, be sure to identify the filename that was included and group accordingly.
- [ ] Create new configurations
  - [ ] Support creating "Include" files.
  - [ ] Support logical grouping through the use of custom configuration comment tags.
  - [ ] Allow user to save configuration file(s) - "Include" files also - to any location the user has write access to.
  - [ ] When saving files, ensure that the proper permissions are applied.
- [ ] Update "in-place" existing configurations
  - [ ] Similar to load and create, must support "Include" files.
  - [ ] Ideally, updates will be atomic - change just the portion that needs to be changed. To begin with I will probably end up just rewriting the entire output.

2. Manage SSH Server Configurations

- [ ] Load existing configurations
- [ ] Create new configurations
- [ ] Update "in-place" existing configurations

3. Manage private / public keys

- [ ] Create new keys form
- [ ] Rename / move keys in the filesystem
- [ ] Maintain a "library" of available keys for use in SSH Client and Server configuration forms.

4. Miscellaneous "quality of life" features

- [ ] UI consistency
  - [x] Use system light / dark mode preference regardless of DE.
  - [x] Fetch basic colors from active KDE theme and apply to the CSS.
  - [ ] Fetch basic colors from active Gnome/GTK theme and apply to the CSS.
- [ ] OS support
  - [x] Linux
  - [ ] Windows
  - [ ] Mac

<!-- :heavy_check_mark: Feature 1;\ -->

## :rocket: Technologies

The following tools were used to build Klortho:

- [Vite](https://vite.dev/)
- [Vitest](https://vitest.dev/)
- [Tauri](https://v2.tauri.app/)
- [React](https://react.dev/)
- [Bun](https://bun.sh/)
- [TailwindCSS](https://tailwindcss.com/)
- [ShadCN/UI](https://ui.shadcn.com/)

## :white_check_mark: Requirements

Make sure you have at least Bun and Rust installed. The rest _should_ install itself.

## :checkered_flag: Starting

```bash
# Clone this project
$ git clone https://github.com/dainbrump/klortho

# Access
$ cd klortho

# Install Javascript/Typescript stuffs
$ bun install

# Then run the dev task
$ bun run tauri dev

# The app should build and launch automatically.
```

## :memo: License

This project is under license from MIT. For more details, see the [LICENSE](LICENSE.md) file.

Made with :heart: by <a href="https://github.com/dainbrump" target="_blank">Mark Litchfield</a>

<a href="#top">Back to top</a>
