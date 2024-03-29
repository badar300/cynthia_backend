# Generated by Django 4.1.7 on 2023-03-21 16:31

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('cynthia_app', '0004_alter_features_estimate_wd_alter_member_comment_and_more'),
    ]

    operations = [
        migrations.CreateModel(
            name='FeatureAssign',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('assigned_team_count', models.IntegerField(default=1)),
                ('assigned_date', models.DateField()),
                ('feature_id', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, related_name='assign_list', to='cynthia_app.features')),
            ],
        ),
    ]
