from django.urls import path
from .views import *
from rest_framework import routers
router = routers.DefaultRouter()
router.register(r'teams', TeamsViewSet, basename='teams')
router.register(r'features', FeaturesViewSet, basename='features')
urlpatterns = [
    path('register', RegisterUserView.as_view(), name='register'),
    path('login', LoginView.as_view(), name='login'),
    # path('features', FeaturesViewSet.as_view(), name='feature'),
    # path('teams', TeamsViewSet, name='team'),
    # path('teams', TeamListAPIView.as_view(), name='team_list'),
    # path('update_feature', UpdateFeatureAPIView.as_view(), name='update_feature'),
    path('reset', reset_email_link, name='reset'),
    path('reset_password', reset_password, name='reset_pass'),
    path('confirm-email/<str:uidb64>/<str:token>/', confirm_email, name='confirm_email'),
    path('get_features', get_user_features, name='get_user_feature'),

]+router.urls
