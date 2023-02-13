# Generated by Django 4.1.3 on 2023-02-11 09:36

from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='Features',
            fields=[
                ('feature_id', models.AutoField(primary_key=True, serialize=False)),
                ('name', models.CharField(max_length=30)),
                ('state', models.CharField(max_length=30)),
                ('estimate_wd', models.FloatField()),
                ('comment', models.CharField(max_length=500)),
            ],
        ),
    ]
