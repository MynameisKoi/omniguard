from importlib import import_module


try:
    YOLO = import_module("ultralytics").YOLO
except ImportError as exc:
    raise ImportError(
        "The 'ultralytics' package is required. Install it with: pip install ultralytics"
    ) from exc


def detect_logo(image_path):

    model = YOLO("yolov8n.pt")

    results = model(image_path)
    
    detected_objects = []

    for result in results:

        boxes = result.boxes

        for box in boxes:

            class_id = int(box.cls[0])
            confidence = float(box.conf[0])

            class_name = result.names[class_id]

            detected_objects.append({
                "object": class_name,
                "confidence": confidence
            })

    return detected_objects