# Generated by Django 4.1.7 on 2023-03-21 17:17

from django.db import migrations, models
import django.utils.timezone


class Migration(migrations.Migration):

    dependencies = [
        ('cynthia_app', '0005_featureassign'),
    ]

    operations = [
        migrations.AddField(
            model_name='features',
            name='create_at',
            field=models.DateTimeField(default=django.utils.timezone.now),
        ),
        migrations.AddField(
            model_name='member',
            name='create_at',
            field=models.DateTimeField(default=django.utils.timezone.now),
        ),
    ]
