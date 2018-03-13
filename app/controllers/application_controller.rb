class ApplicationController < ActionController::Base
  # Prevent CSRF attacks by raising an exception.
  # For APIs, you may want to use :null_session instead.
  protect_from_forgery with: :exception
  before_action :authenticate_user

  private

    def init_github
      #this will help DRY up the sessions and repo controllers by making this a before_action
      @github ||= GithubService.new({access_token: session[:token]})
    end

    def authenticate_user
      redirect_to "https://github.com/login/oauth/authorize?client_id=#{ENV['GITHUB_CLIENT']}&scope=repo" if !logged_in?
    end

    def logged_in?
      !!session[:token]
    end
end
