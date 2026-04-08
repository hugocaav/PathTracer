def api_timeline(request):
    """API endpoint — returns alert count grouped by hour."""
    from django.db.models.functions import TruncHour
    from django.db.models import Count

    timeline = (
        Alert.objects
        .annotate(hour=TruncHour('timestamp'))
        .values('hour')
        .annotate(count=Count('id'))
        .order_by('hour')
    )

    data = [
        {
            'hour': entry['hour'].strftime('%H:%M'),
            'date': entry['hour'].strftime('%b %d'),
            'count': entry['count'],
        }
        for entry in timeline
    ]

    return JsonResponse({'timeline': data})