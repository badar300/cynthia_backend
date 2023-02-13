from django.db import models

# Create your models here.


class Features(models.Model):
    feature_id = models.AutoField(primary_key=True)
    name = models.CharField(max_length=30)
    state = models.CharField(max_length=30)
    estimate_wd = models.FloatField()
    comment = models.CharField(max_length=500)

    def __str__(self):
        return self.name


class Member(models.Model):
    member_id = models.AutoField(primary_key=True)
    name = models.CharField(max_length=30)
    arrival_date = models.DateField(null=False)
    leave_date = models.DateField()
    comment = models.CharField(max_length=500)

    def __str__(self):
        return self.name
