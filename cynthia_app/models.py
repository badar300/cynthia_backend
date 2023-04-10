from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone
# Create your models here.


class Features(models.Model):
    feature_id = models.AutoField(primary_key=True)
    user = models.ForeignKey(User,on_delete=models.CASCADE,null=True,blank=True)
    name = models.CharField(max_length=30)
    state = models.CharField(max_length=30)
    estimate_wd = models.FloatField(null=True,blank=True)
    comment = models.CharField(max_length=500)
    create_at = models.DateTimeField(default=timezone.now)
    def __str__(self):
        return self.name
    class meta:
        verbose_name = "Feature"
        verbose_name_plural = "Feature"


class Member(models.Model):
    user = models.ForeignKey(User,on_delete=models.CASCADE,null=True,blank=True)
    member_id = models.AutoField(primary_key=True)
    name = models.CharField(max_length=30)
    arrival_date = models.DateField(null=False)
    leave_date = models.DateField(null=True,blank=True)
    comment = models.CharField(max_length=500,null=True,blank=True)
    create_at = models.DateTimeField(default=timezone.now)

    def __str__(self):
        return self.name


class FeatureAssign(models.Model):
    feature_id = models.ForeignKey(Features, on_delete=models.CASCADE, null=True, blank=True, related_name='assign_list')
    assigned_team_count = models.IntegerField(default=1)
    assigned_date = models.DateField()
    
