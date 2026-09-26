import { useRef, useEffect }  from 'react'
import cytoscape from 'cytoscape'

function GraphCanvas() {
    // going to write useRef 
    const containerRef = useRef(null);

    // adding useEffect here 
    useEffect(() => {
        // nothing here for now
    }, [])

    return (
        <div ref={containerRef} style={{ height: "500px", width: "100%" }}>
            
        </div>
    )
}

export default GraphCanvas; 