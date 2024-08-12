from rest_framework.response import Response
from rest_framework import status
from rest_framework.views import APIView
from account.serializers import SendPasswordResetEmailSerializer, UserChangePasswordSerializer, UserLoginSerializer, UserPasswordResetSerializer, UserProfileSerializer, UserRegistrationSerializer
from django.contrib.auth import authenticate
from account.renderers import UserRenderer
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.permissions import IsAuthenticated
from rest_framework import generics, permissions, status
from rest_framework.views import APIView
from rest_framework.response import Response
from django.contrib.auth.models import User
from .models import Task, TaskMember
from .serializers import TaskSerializer, TaskMemberSerializer, UserSerializer
from rest_framework_simplejwt.tokens import RefreshToken
from django.shortcuts import get_object_or_404

from .models import *

# Generate Token Manually
def get_tokens_for_user(user):
  refresh = RefreshToken.for_user(user)
  return {
      'refresh': str(refresh),
      'access': str(refresh.access_token),
  }

class UserRegistrationView(APIView):
  renderer_classes = [UserRenderer]
  def post(self, request, format=None):
    serializer = UserRegistrationSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)
    user = serializer.save()
    token = get_tokens_for_user(user)
    return Response({'token':token, 'msg':'Registration Successful'}, status=status.HTTP_201_CREATED)

class UserLoginView(APIView):
  renderer_classes = [UserRenderer]
  def post(self, request, format=None):
    serializer = UserLoginSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)
    email = serializer.data.get('email')
    password = serializer.data.get('password')
    user = authenticate(email=email, password=password)
    if user is not None:
      token = get_tokens_for_user(user)
      return Response({'token':token, 'msg':'Login Success'}, status=status.HTTP_200_OK)
    else:
      return Response({'errors':{'non_field_errors':['Email or Password is not Valid']}}, status=status.HTTP_404_NOT_FOUND)

class UserProfileView(APIView):
  renderer_classes = [UserRenderer]
  permission_classes = [IsAuthenticated]
  def get(self, request, format=None):
    serializer = UserProfileSerializer(request.user)
    return Response(serializer.data, status=status.HTTP_200_OK)

class UserChangePasswordView(APIView):
  renderer_classes = [UserRenderer]
  permission_classes = [IsAuthenticated]
  def post(self, request, format=None):
    serializer = UserChangePasswordSerializer(data=request.data, context={'user':request.user})
    serializer.is_valid(raise_exception=True)
    return Response({'msg':'Password Changed Successfully'}, status=status.HTTP_200_OK)

class SendPasswordResetEmailView(APIView):
  renderer_classes = [UserRenderer]
  def post(self, request, format=None):
    serializer = SendPasswordResetEmailSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)
    return Response({'msg':'Password Reset link send. Please check your Email'}, status=status.HTTP_200_OK)

class UserPasswordResetView(APIView):
  renderer_classes = [UserRenderer]
  def post(self, request, uid, token, format=None):
    serializer = UserPasswordResetSerializer(data=request.data, context={'uid':uid, 'token':token})
    serializer.is_valid(raise_exception=True)
    return Response({'msg':'Password Reset Successfully'}, status=status.HTTP_200_OK)


# views.py
class TaskAPIView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request, pk=None, *args, **kwargs):
        if pk:
            task = get_object_or_404(Task, pk=pk, owner=request.user)
            serializer = TaskSerializer(task)
            return Response(serializer.data)
        else:
            tasks = Task.objects.filter(owner=request.user)
            serializer = TaskSerializer(tasks, many=True)
            return Response(serializer.data)

    def post(self, request, pk=None, *args, **kwargs):
        if pk:
            # Update an existing task
            task = get_object_or_404(Task, pk=pk, owner=request.user)

            # Handle status update
            if 'status' in request.data:
                status_value = request.data.get('status')
                if status_value in dict(Task.STATUS_CHOICES).keys():
                    task.status = status_value
                    task.save()
                    return Response({"detail": "Task status updated successfully"})
                return Response({"detail": "Invalid status"}, status=status.HTTP_400_BAD_REQUEST)
            
            # Update task with new data
            serializer = TaskSerializer(task, data=request.data, partial=True)
            if serializer.is_valid():
                serializer.save()  # No need to include 'owner'
                return Response(serializer.data)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        else:
            # Create a new task
            serializer = TaskSerializer(data=request.data)
            if serializer.is_valid():
                serializer.save(owner=request.user)  # Set owner here
                return Response(serializer.data, status=status.HTTP_201_CREATED)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, pk, *args, **kwargs):
        task = get_object_or_404(Task, pk=pk, owner=request.user)
        task.delete()
        return Response({"detail": "Task deleted successfully"}, status=status.HTTP_204_NO_CONTENT)



# Task Member Operations
class TaskMemberAPIView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request, pk, *args, **kwargs):
        task = get_object_or_404(Task, pk=pk, owner=request.user)
        members = User.objects.filter(task_memberships__task=task)
        serializer = UserSerializer(members, many=True)
        return Response(serializer.data)

    def post(self, request, pk, *args, **kwargs):
        task = get_object_or_404(Task, pk=pk, owner=request.user)
        action = request.data.get("action")
        user_id = request.data.get('user_id')
        user = get_object_or_404(User, pk=user_id)
        
        if action == "add":
            if not TaskMember.objects.filter(task=task, user=user).exists():
                TaskMember.objects.create(task=task, user=user)
                return Response({"detail": "Member added to task"}, status=status.HTTP_201_CREATED)
            return Response({"detail": "User is already a member of this task"}, status=status.HTTP_400_BAD_REQUEST)

        elif action == "remove":
            TaskMember.objects.filter(task=task, user=user).delete()
            return Response({"detail": "Member removed from task"}, status=status.HTTP_204_NO_CONTENT)
        
        return Response({"detail": "Invalid action"}, status=status.HTTP_400_BAD_REQUEST)