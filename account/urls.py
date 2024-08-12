from django.urls import path
from account.views import *
urlpatterns = [
    path('register/', UserRegistrationView.as_view(), name='register'),
    path('login/', UserLoginView.as_view(), name='login'),
    path('profile/', UserProfileView.as_view(), name='profile'),
    path('changepassword/', UserChangePasswordView.as_view(), name='changepassword'),
    path('send-reset-password-email/', SendPasswordResetEmailView.as_view(), name='send-reset-password-email'),
    path('reset-password/<uid>/<token>/', UserPasswordResetView.as_view(), name='reset-password'),

    path('tasks/', TaskAPIView.as_view(), name='task-list-create'),
    path('tasks/<int:pk>/', TaskAPIView.as_view(), name='task-detail'),
    path('tasks/<int:pk>/members/', TaskMemberAPIView.as_view(), name='task-member-list'),
    path('tasks/<int:pk>/members/', TaskMemberAPIView.as_view(), name='task-member-modify'),

]