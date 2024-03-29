import json

from django.contrib.auth import authenticate
from django.contrib.auth.tokens import default_token_generator
from django.http import request, JsonResponse, HttpResponse
from django.shortcuts import render, redirect
from datetime import *
# Create your views here.
from django.template.loader import render_to_string
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from rest_framework import serializers, status
from rest_framework.authentication import SessionAuthentication, BasicAuthentication, TokenAuthentication
import math
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
from django.views.generic import *
from cynthia_app.models import Features, Member, FeatureAssign
from cynthia_app.utils import send_reset_email
from django.db.models import F, Sum


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
        subject = 'Activate Your Cynthia Account'
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
        fields = ['feature_id', 'name', 'state', 'estimate_wd', 'comment']

    def create(self, validated_data):
        user = validated_data.pop("user")
        feature = Features.objects.create(user=user, **validated_data)
        return feature


class FeaturesViewSet(viewsets.ModelViewSet):
    queryset = Features.objects.all()
    serializer_class = FeatureSerializer
    authentication_classes = [SessionAuthentication, BasicAuthentication, TokenAuthentication]
    permission_classes = [permissions.IsAuthenticated]

    def list(self, request):
        queryset = self.get_queryset().filter(user=request.user).order_by('name')
        serializer = self.get_serializer(queryset, many=True)
        return Response(serializer.data)

    def perform_create(self, serializer):
        serializer.save(user=self.request.user)

    def delete(self, request, pk=None):
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


class BaseFeatureAssignSerializer(serializers.ModelSerializer):

    class Meta:
        model = FeatureAssign
        fields = "__all__"

    def update(self, instance, validated_data):
        instance.assigned_team_count = validated_data.get('assigned_team_count', instance.assigned_team_count)
        instance.assigned_date = validated_data.get('assigned_date', instance.assigned_date)
        instance.save()
        return instance

    def create(self, validated_data):
        feature_id = validated_data.get('feature_id')
        assigned_team_count = validated_data.get('assigned_team_count')
        assigned_date = validated_data.get('assigned_date')

        feature_assign = FeatureAssign.objects.create(
            feature_id=feature_id,
            assigned_team_count=assigned_team_count,
            assigned_date=assigned_date
        )
        return feature_assign


class FeatureListSerializer(serializers.ModelSerializer):
    # assign_list = BaseFeatureAssignSerializer(many=True)
    dates = serializers.SerializerMethodField()
    planned = serializers.SerializerMethodField()

    class Meta:
        model = Features
        fields = "__all__"
    
    def get_planned(self, obj):
        return FeatureAssign.objects.filter(feature_id=obj).aggregate(total=Sum(F('assigned_team_count')*5))['total']

    def get_dates(self, obj):
        oldest_f = Features.objects.filter(user=obj.user).exclude(state='Done').order_by("feature_id")[0]
        latest_f = Features.objects.filter(user=obj.user).exclude(state='Done').order_by("-feature_id")[0]
        if oldest_f:
            two_weeks = oldest_f.create_at - timedelta(days=14)
            monday = two_weeks - timedelta(days=two_weeks.weekday())
            number_of_days = (latest_f.create_at - monday).days
            number_of_days = math.ceil(number_of_days/7)
            _dates = []
            number_of_days = 10 if number_of_days < 10 else number_of_days+1
            for i in range(number_of_days):
                temp = (monday + timedelta(days=i * 7)).date()
                feature_assign = FeatureAssign.objects.filter(assigned_date=temp, feature_id=obj).first()
                if feature_assign:
                    temp_dict = {
                        'date': temp,
                        'assinged_feature': {
                            'id': feature_assign.id,
                            'count': feature_assign.assigned_team_count
                        }
                    }
                else:
                    temp_dict = {
                        'date': temp,
                        'assinged_feature': {
                            'id': '',
                            'count': ''
                        }
                    }

                _dates.append(temp_dict)

        return _dates


class FeatureAssignView(viewsets.ModelViewSet):
    serializer_class = FeatureListSerializer
    queryset = Features.objects.all().exclude(state='Done').order_by("name")

    def get_dates(self, obj):
        oldest_f = Features.objects.filter(user=obj).exclude(state='Done').order_by("feature_id")[0]
        latest_f = Features.objects.filter(user=obj).exclude(state='Done').order_by("-feature_id")[0]
        if oldest_f:
            two_weeks = oldest_f.create_at - timedelta(days=14)
            monday = two_weeks - timedelta(days=two_weeks.weekday())
            number_of_days = (latest_f.create_at - monday).days
            number_of_days = math.ceil(number_of_days/7)
            _dates = []
            number_of_days = 10 if number_of_days< 10 else number_of_days+1
            for i in range(number_of_days):
                _dates.append((monday+timedelta(days=i*7)).date())
        return _dates

    def get_planned_fte(self, dates,user):
        available_fte = []
        for date in dates:
            color = "green"
            count = FeatureAssign.objects.filter(assigned_date=date).aggregate(Sum('assigned_team_count'))['assigned_team_count__sum']
            member_count = Member.objects.filter(user=user).count()
            if count and member_count < count:
                color = "red"
            available_fte.append({"count":count,"color": color})
        return available_fte

    def list(self, request, *args, **kwargs):
        user = request.user
        member_count = Member.objects.filter(user=user).count()
        dates = self.get_dates(user)
        planned_fte = self.get_planned_fte(dates,user)
        serializer = self.get_serializer(self.queryset.filter(user=user), many=True)
        return Response({"member_count": member_count, "planned_fte": planned_fte, "dates": dates, "data": serializer.data})

    def update(self, request, pk, *args, **kwargs):
        data = request.data
        data["feature_id"] = pk

        feature_assign = FeatureAssign.objects.filter(feature_id=pk, assigned_date=data['assigned_date']).first()
        if feature_assign:
            serializer = BaseFeatureAssignSerializer(feature_assign, data=data)
        else:
            serializer = BaseFeatureAssignSerializer(data=data)
        if serializer.is_valid():
            serializer.save()
            return Response({"message": "Inserted"}, status=status.HTTP_200_OK)
        else:
            return Response({"error": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)
