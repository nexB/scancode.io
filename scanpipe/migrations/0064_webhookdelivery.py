# Generated by Django 5.0.7 on 2024-07-24 05:22

import django.db.models.deletion
import scanpipe.models
import uuid
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('scanpipe', '0063_run_selected_steps'),
    ]

    operations = [
        migrations.CreateModel(
            name='WebhookDelivery',
            fields=[
                ('uuid', models.UUIDField(db_index=True, default=uuid.uuid4, editable=False, primary_key=True, serialize=False, verbose_name='UUID')),
                ('target_url', models.URLField(help_text='Stores a copy of the Webhook target URL in case the subscription object is deleted.', max_length=1024, verbose_name='Target URL')),
                ('sent_date', models.DateTimeField(auto_now_add=True, help_text='The date and time when the Webhook was sent.')),
                ('payload', models.JSONField(blank=True, default=dict, help_text='The JSON payload that was sent to the target URL.')),
                ('response_status_code', models.PositiveIntegerField(blank=True, help_text='The HTTP status code received in response to the Webhook request.', null=True)),
                ('response_text', models.TextField(blank=True, help_text='The text response received from the target URL.')),
                ('delivery_error', models.TextField(blank=True, help_text='Any error messages encountered during the Webhook delivery.')),
                ('project', models.ForeignKey(editable=False, on_delete=django.db.models.deletion.CASCADE, related_name='%(class)ss', to='scanpipe.project')),
                ('webhook_subscription', models.ForeignKey(blank=True, editable=False, help_text='The Webhook subscription associated with this delivery.', null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='deliveries', to='scanpipe.webhooksubscription')),
            ],
            options={
                'abstract': False,
            },
            bases=(scanpipe.models.UpdateMixin, models.Model),
        ),
    ]
