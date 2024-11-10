#include "utils.h"
#include <QDateTime>
QString formatTimestamp(qint64 timestamp)
{
    return QDateTime::fromMSecsSinceEpoch(timestamp)
        .toString("yyyy-MM-dd hh:mm:ss.zzz");
}
