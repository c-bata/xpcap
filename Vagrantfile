# -*- mode: ruby -*-
# vi: set ft=ruby :
VAGRANTFILE_API_VERSION = "2"

box = "bento/ubuntu-18.04"

Vagrant.configure(VAGRANTFILE_API_VERSION) do |config|
  config.vm.box = box
  config.vm.network "public_network"
  config.vm.synced_folder ".", "/home/vagrant/xpcap"
  config.vm.provider "virtualbox" do |vb|
    vb.memory = "1024"
  end

  config.vm.provision "shell", inline: <<-SHELL
    set -e
    apt-get update
    apt-get install -y git tmux vim wget build-essential

    cat >/home/vagrant/.gitconfig <<EOF
[color]
        ui = true
[core]
        editor = /usr/bin/vim
[alias]
        s   = status
        st  = status
        ss  = status -s
        b   = branch
        co  = checkout
        lg = log --graph --pretty=format:'%Cred%h%Creset -%C(yellow)%d%Creset %s %Cgreen(%cr) %C(bold blue)<%an>%Creset' --abbrev-commit --date=relative
        lga = log --graph --all --pretty=format:'%Cred%h%Creset -%C(yellow)%d%Creset %s %Cgreen(%cr) %C(bold blue)<%an>%Creset' --abbrev-commit --date=relative
EOF

    cat >/home/vagrant/.vimrc <<EOF
set number
syntax on

"" Directories for swp files
set noswapfile
set nobackup
set autoindent
set clipboard=unnamed,autoselect
set ruler

"" Encoding
set encoding=utf-8
set fileencoding=utf-8
set fileencodings=utf-8
set bomb
set ttyfast
set binary

"" Tabs. May be overriten by autocmd rules
set tabstop=4
set softtabstop=0
set shiftwidth=4

"" Searching
set hlsearch
set incsearch
set ignorecase
set smartcase

autocmd FileType html,css,markdown,tex setlocal tabstop=2 shiftwidth=2 softtabstop=2

autocmd FileType python setlocal expandtab shiftwidth=4 tabstop=8 colorcolumn=79 formatoptions+=croq softtabstop=4 smartindent cinwords=if,elif,else,for,while,try,except,finally,def,class,with

set list
set listchars=tab:>-,trail:-,nbsp:%,extends:>,precedes:<

highlight ZenkakuSpace cterm=underline ctermfg=lightblue guibg=#666666
au BufNewFile,BufRead * match ZenkakuSpace /　/
EOF

    cat >/home/vagrant/.tmux.conf <<EOF
setw -g mode-keys vi
set -g prefix C-t
unbind C-b
bind C-t send-prefix
EOF

    cat >>/home/vagrant/.bashrc <<EOF
function gits { git s; git lga -n 10; git b | grep "*"; }
EOF
  SHELL
end

