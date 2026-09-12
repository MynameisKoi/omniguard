import { useState, useEffect } from 'react';


function App() {
    // adding the state for alerts
    const [alerts, setAlerts] = useState([])

    // adding the state for error
    const [error, setError] = useState(null)

    // we will fetch the alerts from backend
    useEffect(() => {
        fetch("http://localhost:8000/alerts")
        .then((res) => res.json())
        .then((data) => setAlerts(data))
        .catch(err => setError(err.message))
    }, []);

    return (
        <div>
            <h1>OmniGuard SOC Alerts Count: {alerts.length}</h1>
                {
                    alerts.map((a) => (
                        <div key={a.alert_id}>
                            <h3>{a.event_type}</h3>
                            <p>Severity: {a.severity}</p>
                            <p>Host: {a.host}</p>
                            <p>User: {a.user || '-'}</p>
                            <p>Domain: {a.domain || '-'}</p>
                            <p>Status: {a.status}</p>
                        </div>
                    ))
                }
        </div>
    )
}

export default App;