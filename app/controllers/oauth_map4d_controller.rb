class OauthMap4dController < ApplicationController
  skip_authorization_check :only => [:signin, :handle_code]
  require 'net/http'
  require 'json'

  layout "site"

  # Redirect to Account Map4D
  def signin
        if(params.has_key?(:referer))
		session[:referer] = params[:referer]
	end
  	redirect_to Settings.map4d_auth_domain + "/oauth/authorize?response_type=code&client_id=" + Settings.map4d_auth_id + "&redirect_uri=" + Settings.map4d_auth_redirect_uri
  end

  # Handle code
  def handle_code
  	if(params.has_key?(:code))
  		@data = get_access_token(params[:code])
  		if (@data['access_token'])
  			@user_info = get_user_info(@data['access_token'])
  			if(@user_info)

  				@user = User.find_by_email(@user_info['email'])
  				if(!@user)
  					@user = User.new( 
					  :email => @user_info['email'],
					  :email_confirmation => @user_info['email'],
					  :display_name => @user_info['name'],
					  :auth_provider => 'map4d',
					  :auth_uid => @user_info['id'],
					  :status => 'pending',
					  :pass_crypt => @user_info['email'],
					  :pass_crypt_confirmation => @user_info['email'],
					  :email_valid => true,
					  :data_public => true,
					  :creation_ip => request.remote_ip,
					  :languages => http_accept_language.user_preferred_languages,
					  :terms_agreed => Time.now.getutc,
					  :terms_seen => true
			  		)
  					@u = @user.save
  				end

          if(@user.status == 'active' || @user.status == 'confirmed')
  			    successful_login(@user)
          end
  			end

        if(@user.status == 'pending')
          unconfirmed_login(@user)
        end
  		end
    end
  end

    # process a successful login
  def successful_login(user, referer = nil)
    session[:user] = user.id
    session_expires_after 28.days if session[:remember_me]
	puts "Session #{session[:referer]}"
    target = referer || session[:referer] || url_for(:controller => :site, :action => :index)

    # The user is logged in, so decide where to send them:
    #
    # - If they haven't seen the contributor terms, send them there.
    # - If they have a block on them, show them that.
    # - If they were referred to the login, send them back there.
    # - Otherwise, send them to the home page.
    if !user.terms_seen
      redirect_to :controller => :users, :action => :terms, :referer => target
    elsif user.blocked_on_view
      redirect_to user.blocked_on_view, :referer => target
    else
      redirect_to target
    end

    session.delete(:remember_me)
    session.delete(:referer)
  end

  # Get access token by code from account.map4d.vn
  def get_access_token(code)
    begin
        uri = URI(Settings.map4d_auth_domain + "/oauth/access_token")
        http = Net::HTTP.new(uri.host, uri.port)
        req = Net::HTTP::Post.new(uri.path, {'Content-Type' =>'application/json'})
        req.body = {
        	'code' => code,
        	'client_id' => Settings.map4d_auth_id,
        	'client_secret' => Settings.map4d_auth_secret,
        	'grant_type' => 'authorization_code',
        	'redirect_uri' =>  Settings.map4d_auth_redirect_uri

	   }.to_json
        res = http.request(req)
        return JSON.parse(res.body)
    rescue => e
        puts "failed #{e}"
        return ""
    end
  end

  # Get user info by access token from account.map4d.vn
  def get_user_info(access_token)
  	begin
        uri = URI('http://account.map4d.vn/api/get-user-info')
        http = Net::HTTP.new(uri.host, uri.port)

        @headers = {
		    'Authorization'=>'Bearer ' + access_token,
		    'Content-Type' =>'application/json',
		    'Accept'=>'application/json'
		}

        req = Net::HTTP::Get.new(uri.path, @headers)
        res = http.request(req)

        return JSON.parse(res.body)
    rescue => e
        puts "failed #{e}"
        return ""
    end
  end

  ##
  #
  def unconfirmed_login(user)
    session[:token] = user.tokens.create.token

    redirect_to :controller => "users", :action => "confirm", :display_name => user.display_name

    session.delete(:remember_me)
    session.delete(:referer)
  end

end
