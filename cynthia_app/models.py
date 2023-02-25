from django.db import models
from django.contrib.auth.models import User
# Create your models here.


class Features(models.Model):
    feature_id = models.AutoField(primary_key=True)
    user = models.ForeignKey(User,on_delete=models.CASCADE,null=True,blank=True)
    name = models.CharField(max_length=30)
    state = models.CharField(max_length=30)
    estimate_wd = models.FloatField(null=True,blank=True)
    comment = models.CharField(max_length=500)

    def __str__(self):
        return self.name


class Member(models.Model):
    user = models.ForeignKey(User,on_delete=models.CASCADE,null=True,blank=True)
    member_id = models.AutoField(primary_key=True)
    name = models.CharField(max_length=30)
    arrival_date = models.DateField(null=False)
    leave_date = models.DateField(null=True,blank=True)
    comment = models.CharField(max_length=500,null=True,blank=True)

    def __str__(self):
        return self.name
