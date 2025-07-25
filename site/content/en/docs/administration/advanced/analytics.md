---
title: 'CVAT Analytics and monitoring'
linkTitle: 'CVAT Analytics and monitoring'
weight: 20
description: 'Instructions for deployment and customization of analytics and monitoring.'
---

CVAT Analytics suite of tools is designed to track and understand users' behavior, system performance,
and for identifying potential issues in your application.

You can also visualize user activity through Grafana, and aggregate user
working time by the jobs.

Gathered logs can be additionally filtered for efficient debugging.

By using analytics, you'll gain valuable insights to optimize your system
and enhance user satisfaction.

CVAT analytics are available from the top menu.

Superusers and users with administrator role have access to analytics.
Permission to access analytics can also be granted when editing a user
on admin page by `Has access to analytics` checkbox.

![CVAT Analytics](/images/analytics_menu.jpg)

> Note: CVAT analytics and monitoring are available only for on-prem solution.

See:

- [High-level architecture](#high-level-architecture)
- [CVAT Analytics](#cvat-analytics)
  - [Ports settings](#ports-settings)
  - [Events log structure](#events-log-structure)
  - [Types of supported events](#types-of-supported-events)
  - [Working time calculation](#working-time-calculation)
  - [Request `id` for tracking](#request-id-for-tracking)
  - [Fetching event data as CSV from the `/api/events` endpoint](#fetching-event-data-as-csv-from-the-apievents-endpoint)
- [Dashboards](#dashboards)
  - [Dashboard: All Events](#dashboard-all-events)
  - [Dashboard: Management](#dashboard-management)
  - [Dashboard: Monitoring](#dashboard-monitoring)
  - [Dashboards setup](#dashboards-setup)
- [Example of use](#example-of-use)

## High-level architecture

The CVAT analytics is based on Vector, ClickHouse, and Grafana.

![CVAT Analytics](/images/analytic_architecture.jpg)

## CVAT Analytics

CVAT and its analytics module can be set up locally, for
self-hosted solution analytics are enabled by default.

> For detailed CVAT installation instructions, see
> {{< ilink "/docs/administration/basics/installation" "Installation Guide" >}}
> or refer to the [CVAT Course](https://www.youtube.com/playlist?list=PL0to7Ng4PuuYQT4eXlHb_oIlq_RPeuasN)
> for installation videos.

All analytics-related features will be launched when you
start CVAT containers with the following command:

```shell
docker compose up -d
```

### Ports settings

If you cannot access analytics on
development environment,
see {{< ilink "/docs/contributing/development-environment#cvat-analytics-ports" "Analytics Ports" >}}

### Events log structure

[Relational database](https://github.com/cvat-ai/cvat/blob/develop/components/analytics/clickhouse/init.sh)
schema with the following fields:

<!--lint disable maximum-line-length-->

| Field      | Description                                                                                      |
| ---------- | ------------------------------------------------------------------------------------------------ |
| scope      | Scope of the event (e.g., `zoomin:image`, `add:annotations`, `delete:image`, `update:assignee`). |
| obj_name   | Object name or None (e.g., task, job, cloudstorage, model, organization).                        |
| obj_id     | Object identifier as in DB or None.                                                              |
| obj_val    | Value for the event as string or None (e.g., frame number, number of added annotations).         |
| source     | Who generates the log event (e.g., server, ui).                                                  |
| timestamp  | Local event time (in general for UI and server, the time is different).                          |
| count      | How many times in the row it occurs.                                                             |
| duration   | How much time does it take (it can be 0 for events without duration).                            |
| project_id | Project ID or None.                                                                              |
| task_id    | Task ID or None.                                                                                 |
| job_id     | Job ID or None.                                                                                  |
| user_id    | User ID or None.                                                                                 |
| user_name  | User name or None.                                                                               |
| user_email | User email or None.                                                                              |
| org_id     | Organization ID or None.                                                                         |
| org_slug   | Organization slug or None.                                                                       |
| payload    | JSON payload or None. Extra fields can be added to the JSON blob.                                |

<!--lint enable maximum-line-length-->

### Types of supported events

Supported events change the scope of information displayed in Grafana.

![Supported Events](/images/supported_events.jpg)

<!--lint disable maximum-line-length-->

Server events:

- `create:project`, `update:project`, `delete:project`

- `create:task`, `update:task`, `delete:task`

- `create:job`, `update:job`, `delete:job`

- `create:organization`, `update:organization`, `delete:organization`

- `create:user`, `update:user`, `delete:user`

- `create:cloudstorage`, `update:cloudstorage`, `delete:cloudstorage`

- `create:issue`, `update:issue`, `delete:issue`

- `create:comment`, `update:comment`, `delete:comment`

- `create:annotations`, `update:annotations`, `delete:annotations`

- `create:label`, `update:label`, `delete:label`

- `export:dataset`, `import:dataset`

- `call:function`

- `create:membership`, `update:membership`, `delete:membership`

- `create:webhook`, `update:webhook`, `delete:webhook`

- `create:invitation`, `delete:invitation`

Client events:

- `load:cvat`

- `load:job`, `save:job`

- `send:exception`

- `draw:object`, `paste:object`, `copy:object`, `propagate:object`, `drag:object`, `resize:object`, `delete:object`, `merge:objects`, `split:objects`, `group:objects`, `slice:object`,
`join:objects`

- `change:frame`

- `zoom:image`, `fit:image`, `rotate:image`

- `action:undo`, `action:redo`

- `run:annotations_action`

- `click:element`

- `debug:info`

<!--lint enable maximum-line-length-->

### Working time calculation

Here is a short overview of how CVAT deals with the user's working time:

- The user interface collects events when a user interacts with the interface
  (resizing canvas, drawing objects, clicking buttons, etc)
  The structure of one single event is described [here](#events-log-structure).

- The user interface sends these events in bulk to the server.
  Currently, it uses the following triggers to send events:
  - Periodical timer (~90 seconds)
  - A user clicks the "Save" button on the annotation view
  - A user opens the annotation view
  - A user closes the annotation view (but not the tab/browser)
  - A user clicks **Logout** button

- When events reach the server, it calculates working time based on timestamps of the events.

- The working time for an event is computed as the sum of the following:
  - The difference between the start time of the event and the end time of
    the previous event, if it is not more than 100 seconds.
  - The duration of the event, for events of type `change:frame`.

- After calculation, the server generates `send:working_time` events with time value in payload.
  These events may or may not be bound to a certain job/task/project,
  depending on the client-side events that were used to generate them.

- CVAT saves the event in the database and later these events are used to compute metrics for analytics.

### Request `id` for tracking

Note, that every response to an API request made to the
the server includes a header named `X-Request-Id`,
for example: `X-Request-Id: 6a2b7102-c4b9-4d57-8754-5658132ba37d`.

This identifier is also recorded in all server events that
occur as a result of the respective request.

For example, when an operation to create a task is performed,
other related entities such as labels and attributes are
generated on the server in addition to the **Task** object.

All events associated with this operation will have the same `request_id` in
the payload field.

### Export event data

You can export the event data as a CSV file locally and to cloud storage.

To export the data locally:
1. Initiate the export process by sending a `POST` request to `/api/events/export` endpoint.
   The endpoint accepts several query parameters to filter events:
   `org_id`, `project_id`, `task_id`, `job_id`, `user_id`, `to` and `from`.
   For more details, see
   [Swagger API Documentation](https://app.cvat.ai/api/swagger/#/events/events_create_export).
   For example:

   ```bash
   curl -X POST -u 'user:pass' https://app.cvat.ai/api/events/export?job_id=123
   ```

1. You can check the status of the export process by sending a GET request with the `rq_id` to the
   [`/api/requests/{id}`](https://app.cvat.ai/api/swagger/#/requests/requests_retrieve) endpoint:

   ```bash
   curl -I --user 'user:pass' https://app.cvat.ai/api/requests/rq_id
   ```

   Once the export process finishes, the request returns an object with `"status": "finished"` and `"result_url": "URL"`.

1. Download the event data file locally using `result_url`:
   ```bash
   curl -u user:password -o path/to/file.csv result_url
   ```

   This command will download and save the CSV file to `path/to/file.csv` on your local machine.


To save the CSV file with the event data to cloud storage, you can use the
`/api/events/export` endpoint with `cloud_storage_id` and `location=cloud_storage` parameters,
for example:

```bash
curl -X POST -u user:password "https://app.cvat.ai/api/events/export?cloud_storage_id=your_cloud_storage_id&location=cloud_storage"
```

## Dashboards

By default, three dashboards are available in CVAT.

To access them, click **General**, you will be forwarded to the
page with available dashboards.

![List of dashboards](/images/dashboard_00.jpg)

<!--lint disable maximum-line-length-->

| Dashboard      | Description                                                                             |
| -------------- | --------------------------------------------------------------------------------------- |
| **All Events** | Dashboard that shows all event logs, timestamps, and source.                            |
| **Management** | Dashboard with information about user activities such as working time by job and so on. |
| **Monitoring** | Dashboard showing server logs, including errors.                                        |

<!--lint enable maximum-line-length-->

### Dashboard: All Events

The dashboard shows all events, their timestamps, and their source.

![Dashboard: All Events](/images/dashboard_01.jpg)

<!--lint disable maximum-line-length-->

| Element              | Description                                                                                                                |
| -------------------- | -------------------------------------------------------------------------------------------------------------------------- |
| **Filters**          | Can be used as drop-down lists or search fields. Click on the arrow to activate.                                           |
| **Overall activity** | Graph that shows the overall activity by the selected filters.                                                             |
| **Scope**            | Users' activity, see [Types of supported events](#types-of-supported-events).                                              |
| **obj_name**         | Object or item related to the **Scope**.                                                                                   |
| **obj_id**           | Object's id. Might be empty.                                                                                               |
| **source**           | Source of the event, can be `client` or `server`.                                                                          |
| **timestamp**        | Time when the event happened.                                                                                              |
| **count**            | Common field for all events, not null where it makes sense, for example, the <br>number of saved objects in an annotation. |
| **duration**         | Duration in milliseconds.                                                                                                  |
| **project_id**       | Id of the project.                                                                                                         |
| **project_id**       | Id of the project.                                                                                                         |
| **task_id**          | ID of the task.                                                                                                            |
| **job_id**           | ID of the job.                                                                                                             |

<!--lint enable maximum-line-length-->

There are two fields with statistics at the bottom of the dashboard,
about browser and OS users use.

Click on the column name to enable a filter.

If you want to inspect the value, hover over it and click
on the eye icon.

### Dashboard: Management

The dashboard shows user activity.

![Dashboard: Management](/images/dashboard_02.jpg)

<!--lint disable maximum-line-length-->

| Element              | Description                                                                                                                     |
| -------------------- | ------------------------------------------------------------------------------------------------------------------------------- |
| **Filters**          | Can be used as drop-down lists or search fields. Click on the arrow to activate.                                                |
| **User activity**    | Graph that shows when the user was active (data and time), click on the user id below, to see the graph for the dedicated user. |
| **Overall activity** | Graph shows common activity for all users.                                                                                      |
| **User**             | User ID.                                                                                                                        |
| **Project**          | Project ID. Might be empty.                                                                                                     |
| **Task**             | Task ID. Might be empty.                                                                                                        |
| **Job**              | Job ID. Might be empty.                                                                                                         |
| **Working time(h)**  | Time spent on task in hours.                                                                                                    |
| **Activity**         | Number of events for each user.                                                                                                 |

<!--lint enable maximum-line-length-->

Click on the column name to enable a filter.

If you want to inspect the value, hover over it and click
on the eye icon.

### Dashboard: Monitoring

The dashboard shows server logs, helps handle errors, and shows user activity.

![Dashboard: Monitoring](/images/dashboard_03.jpg)

<!--lint disable maximum-line-length-->

| Element                | Description                                                                                                                                                                                                                        |
| ---------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Filters**            | Can be used as drop-down lists or search fields. Click on the arrow to activate.                                                                                                                                                   |
| **Active users (now)** | Number of active users on an instance.                                                                                                                                                                                             |
| **Overall activity**   | Graph that shows the number of active users.                                                                                                                                                                                       |
| **Exceptions**         | Graph that shows the number of errors that happened in the instance.                                                                                                                                                               |
| **timestamp**          | Time when the error happened.                                                                                                                                                                                                      |
| **user_id**            | User ID.                                                                                                                                                                                                                           |
| **user_name**          | User nickname.                                                                                                                                                                                                                     |
| **project_id**         | Id of the project. Might be empty.                                                                                                                                                                                                 |
| **task_id**            | Task ID. Might be empty.                                                                                                                                                                                                           |
| **job_id**             | Job ID. Might be empty.                                                                                                                                                                                                            |
| **error**              | Error description                                                                                                                                                                                                                  |
| **stack**              | Error description                                                                                                                                                                                                                  |
| **payload**            | Error description                                                                                                                                                                                                                  |
| **stack**              | Stack trace, which is a report of the active stack frames at a certain point in time during the execution. This information is typically used for debugging purposes to locate where an issue occurred.                            |
| **payload**            | JSON that describes the entire object, which contains several properties. This data in the payload is related to an event that was created as a result of a failed API request. The payload contains information about this event. |

<!--lint enable maximum-line-length-->

Click on the column name to enable a filter.

If you want to inspect the value, hover over it and click
on the eye icon.

### Dashboards setup

You can adjust the dashboards. To do this, click on the
graph or table name and from the drop-down menu select **Edit**.

Adjust the query in the editor.

![Dashboard: look and feel](/images/dashboard_04.jpg)

Example of query:

```sql
SELECT
    time,
    uniqExact(user_id) Users
FROM
(
    SELECT
      user_id,
      toStartOfInterval(timestamp, INTERVAL 15 minute) as time
    FROM cvat.events
    WHERE
      user_id IS NOT NULL
    GROUP BY
      user_id,
      time
    ORDER BY time ASC WITH FILL STEP toIntervalMinute(15)
)
GROUP BY time
ORDER BY time
```

> **Note**, that by default the updated configuration will not be saved
> and will be reset to the default parameters after you restart the
> container.

To save the updated configuration, do the following:

1. **Update Configuration**: Start by making your desired changes in the query.

1. **Apply Changes**: Once you've made your changes,
   click the **Apply** button to ensure the changes are implemented.

   ![Apply changes](/images/apply.jpg)

1. **Save Configuration**: To save your applied changes, on the top of the dashboard,
   click the **Save** button.

   ![Apply changes](/images/save_results.jpg)

1. **Replace Configuration File**: After saving, replace the existing
   Grafana dashboard configuration file is located at
   `components/analytics/grafana/dashboards` with the new JSON configuration file.

   ![Apply changes](/images/save_json.jpg)

1. **Restart Grafana Service**: To ensure, that all changes take effect,
   restart the Grafana service. If you're using Docker Compose,
   execute the following command: `docker compose restart cvat_grafana`.

For more information,
see [Grafana Dashboards](https://grafana.com/docs/grafana/latest/dashboards/).

## Example of use

This video demonstrates available by default CVAT analytics features.

<!--lint disable maximum-line-length-->

<iframe width="560" height="315" src="https://www.youtube.com/embed/-1kiLPidXpI" title="YouTube video player" frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture; web-share" allowfullscreen></iframe>

<!--lint enable maximum-line-length-->
