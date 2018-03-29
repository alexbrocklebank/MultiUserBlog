# Multi-User-Blog
Multi-User Blog Project for Udacity Full-Stack Web Development Nanodegree

## Requirements
+ Conda
+ Git
+ google appengine


## Instructions
1. Clone git repository: `git clone https://github.com/alexbrocklebank/MultiUserBlog.git`.
2. Open command prompt or terminal in MultiUserBlog folder.
1. Create conda environment: `conda create -n blog_env --file package-list.txt`.
1. Activate conda environment by using the appropriate command for your operating system: `activate blog_env` for Windows or `source activate blog_env` for Mac/Linux users.
2. Install `conda install -c pmlandwehr appengine`.
1. Install Google App Engine through the Google Cloud SDK by following [these instructions](https://cloud.google.com/sdk/docs/).
1. Install Google App Engine components by entering `gcloud components install app-engine-python` and `gcloud components install app-engine-python-extras` into the command line after successfully installing Google Cloud SDK.
1. Set up the app with `gcloud app setup`.
1. Run local server with the command: `dev_appserver blog/app.yaml`

[Public link](https://helloworld-150803.appspot.com/blog)

## Frameworks Used
Google App Engine
Jinja2
Bootstrap 3

## Site Hierarchy
+ home
+ welcome
+ login
+ logout
+ post
  + editpost
  + deletepost
  + addpost
