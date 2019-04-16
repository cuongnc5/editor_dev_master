require 'test_helper'

class OauthMap4dControllerTest < ActionDispatch::IntegrationTest
  test "should get signin" do
    get oauth_map4d_signin_url
    assert_response :success
  end

end
