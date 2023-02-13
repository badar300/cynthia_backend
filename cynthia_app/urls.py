from django.urls import path
from .views import RegisterUserView, LoginView, confirm_email, AddFeatureAPIView, reset_email_link, reset_password, TeamListAPIView,AddTeamMember

urlpatterns = [
    path('register', RegisterUserView.as_view(), name='register'),
    path('login', LoginView.as_view(), name='login'),
    path('add_feature', AddFeatureAPIView.as_view(), name='feature'),
    path('add_member', AddTeamMember.as_view(), name='team'),
    path('teams', TeamListAPIView.as_view(), name='team_list'),
    # path('update_feature', UpdateFeatureAPIView.as_view(), name='update_feature'),
    path('reset', reset_email_link, name='reset'),
    path('reset_password', reset_password, name='reset_pass'),
    path('confirm-email/<str:uidb64>/<str:token>/', confirm_email, name='confirm_email'),

]
