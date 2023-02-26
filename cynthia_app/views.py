import json

from django.contrib.auth import authenticate
from django.contrib.auth.tokens import default_token_generator
from django.http import request, JsonResponse, HttpResponse
from django.shortcuts import render, redirect

# Create your views here.
from django.template.loader import render_to_string
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from rest_framework import serializers, status
from rest_framework.authentication import SessionAuthentication, BasicAuthentication, TokenAuthentication

from django.contrib.auth.models import User
from rest_framework import views, permissions, generics
from rest_framework.exceptions import ValidationError
from rest_framework.renderers import JSONRenderer
from rest_framework.response import Response
from django.core.mail import EmailMessage
from rest_framework.decorators import action
from rest_framework.authtoken.models import Token
from rest_framework import viewsets
from django.utils.decorators import method_decorator

from cynthia_app.models import Features, Member
from cynthia_app.utils import send_reset_email


class SignupSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)

    class Meta:
        model = User
        fields = ('email', 'password')

    def validate_email(self, value):
        if User.objects.filter(email=value).exists():
            raise ValidationError("A user with this email already exists.")
        return value

    def create(self, validated_data):
        user = User.objects.create_user(
            validated_data['email'].split('@'),
            validated_data['email'],

            is_active=True
        )
        user.set_password(validated_data['password'])
        # Token.objects.create(user=user)
        return user


from rest_framework import generics
# from .serializers import UserSerializer


class RegisterUserView(generics.CreateAPIView):
    serializer_class = SignupSerializer

    def send_activation_email(self, email, user):
        subject = 'Activate Your Account'
        message = render_to_string('email.html', {
            'user': user,
            'domain': 'localhost:8000',
            'uid': urlsafe_base64_encode(force_bytes(user.id)),
            'token': default_token_generator.make_token(user),
        })
        # message = f'http://localhost:8000/activate/{user_id}'
        to_email = email
        email = EmailMessage(subject, message, to=[to_email])
        email.send()

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        self.perform_create(serializer)
        user = serializer.instance
        user.save()
        self.send_activation_email(user.email, user)
        # token, created = Token.objects.get_or_create(user=user)
        print(request.data)
        return Response({
            # 'token': token.key,
            'user_id': user.id,
            'username': user.username
        }, status=status.HTTP_201_CREATED)


from rest_framework.views import APIView


class LoginView(APIView):
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        email = request.data.get("email")
        password = request.data.get("password")
        print(email, password)
        user = User.objects.filter(email=email).first()
        if user and user.check_password(password):
            token, created = Token.objects.get_or_create(user=user)
            return Response({'token': token.key})
        return Response({"error": "Invalid credentials"}, status=400)


def confirm_email(request, uidb64, token):
    try:
        uid = urlsafe_base64_decode(uidb64).decode()
        user = User.objects.get(pk=uid)
    except (TypeError, ValueError, OverflowError, User.DoesNotExist):
        user = None

    if user is not None and default_token_generator.check_token(user, token):
        user.is_active = True
        user.save()
        # response=Response({
        #     # 'token': token.key,
        #     'active': user.is_active,
        #     'user_id': user.id,
        #     'username': user.username
        # }, status=status.HTTP_200_OK)
        # response['Content-Type'] = 'application/json'
        # response.accepted_renderer = JSONRenderer()
        # response.accepted_media_type = 'application/json'
        # response.renderer_context = {'some_context_info': 'some_value'}
        # return response
        return redirect('http://localhost:5173/login')

    else:
        return Response({
            # 'token': token.key,
            'active': user.is_active,
            'user_id': user.id,
            'username': user.username
        }, status=status.HTTP_204_NO_CONTENT)


class FeatureSerializer(serializers.ModelSerializer):
    class Meta:
        model = Features
        fields = ['feature_id', 'name', 'state', 'estimate_wd', 'comment',"user"]

    def create(self, validated_data):
        request = self.context.get('request')
        feature = Features.objects.create(user=request.user, **validated_data)
        return feature

    def update(self, instance, validated_data):
        instance.name = validated_data.get('name', instance.name)
        instance.state = validated_data.get('state', instance.state)
        instance.estimate_wd = validated_data.get('estimate_wd', instance.estimate_wd)
        instance.comment = validated_data.get('comment', instance.comment)
        instance.save()
        return instance


class FeaturesViewSet(viewsets.ModelViewSet):
    queryset = Features.objects.all()
    serializer_class = FeatureSerializer
    permission_classes = [permissions.IsAuthenticated]
    def perform_create(self, serializer):
        serializer.save(request=self.request)

    def delete_feature(self, request, pk=None):
        feature = self.get_object()
        if feature.user != request.user:
            return Response({'message': 'Unauthorized'}, status=status.HTTP_401_UNAUTHORIZED)
        feature.delete()
        return Response({'message': 'Feature deleted successfully'}, status=status.HTTP_204_NO_CONTENT)
    def update(self, request, *args, **kwargs):
        partial = kwargs.pop('partial', False)
        feature = self.get_object()
        if feature.user != request.user:
            return Response({'message': 'Unauthorized'}, status=status.HTTP_401_UNAUTHORIZED)
        serializer = self.get_serializer(feature, data=request.data, partial=partial)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(serializer.data)
def update_feature(request):
    data = json.loads(request.body.decode('utf-8'))
    id = data.get('feature_id')
    User.objects.update_or_create(feature_id=id, **data)


def reset_email_link(request):
    import json
    data = json.loads(request.body.decode('utf-8'))
    email = data.get('email')
    print(email)
    user = User.objects.filter(email=email).first()
    if user:
        status, msg = send_reset_email(email, user)
        if status:
            response = JsonResponse({'message': 'message has been send', 'user_id': user.id})
            return response
    return JsonResponse({'error': 'Please try again'})


def reset_password(request):
    if request.method == 'POST':
        data = json.loads(request.body.decode('utf-8'))
        user_id = data['user_id']
        password = data['password']
        try:
            user = User.objects.filter(id=user_id).first()
        except User.DoesNotExist:
            return JsonResponse({'error': 'User not found'}, status=400)
        user.set_password(password)
        user.save()
        return JsonResponse({'message': 'Password reset successful'})


class TeamSerializer(serializers.ModelSerializer):
    class Meta:
        model = Member
        fields = ['member_id','name', 'arrival_date', 'leave_date', 'comment']

    def create(self, validated_data):
        user = validated_data.pop("user")
        team = Member.objects.create(user=user, **validated_data)
        return team


# class AddTeamMember(generics.CreateAPIView):
#     # print(validated_data)
#     print('request a rhi haai 22')
#     serializer_class = TeamSerializer


# class TeamListAPIView(generics.ListAPIView):
#     queryset = Member.objects.all()
#     serializer_class = TeamSerializer

class TeamsViewSet(viewsets.ModelViewSet):
    queryset = Member.objects.all()
    serializer_class = TeamSerializer
    authentication_classes = [SessionAuthentication, BasicAuthentication, TokenAuthentication]
    permission_classes = [permissions.IsAuthenticated]

    def list(self, request):
        queryset = self.get_queryset().filter(user=request.user)
        serializer = self.get_serializer(queryset, many=True)
        return Response(serializer.data)

    def perform_create(self, serializer):
        serializer.save(user=self.request.user)

    def delete(self, request, pk=None):
        team = self.get_object()
        if team.user != request.user:
            return Response({'message': 'Unauthorized'}, status=status.HTTP_401_UNAUTHORIZED)
        team.delete()
        return Response({'message': 'Teams deleted successfully'}, status=status.HTTP_204_NO_CONTENT)

    def update(self, request, *args, **kwargs):
        partial = kwargs.pop('partial', False)
        team = self.get_object()
        if team.user != request.user:
            return Response({'message': 'Unauthorized'}, status=status.HTTP_401_UNAUTHORIZED)
        serializer = self.get_serializer(team, data=request.data, partial=partial)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(serializer.data)