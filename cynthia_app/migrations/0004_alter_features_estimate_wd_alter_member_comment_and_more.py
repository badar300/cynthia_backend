# Generated by Django 4.1.7 on 2023-02-25 07:05

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('cynthia_app', '0003_features_user_member_user'),
    ]

    operations = [
        migrations.AlterField(
            model_name='features',
            name='estimate_wd',
            field=models.FloatField(blank=True, null=True),
        ),
        migrations.AlterField(
            model_name='member',
            name='comment',
            field=models.CharField(blank=True, max_length=500, null=True),
        ),
        migrations.AlterField(
            model_name='member',
            name='leave_date',
            field=models.DateField(blank=True, null=True),
        ),
    ]
