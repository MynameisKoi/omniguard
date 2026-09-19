from PIL import Image  # type: ignore[import-unresolved]
import imagehash  # type: ignore[import-unresolved]


def calculate_phash(image_path):

    image = Image.open(image_path)

    hash_value = imagehash.phash(image)

    return hash_value


def compare_images(image1_path, image2_path):

    hash1 = calculate_phash(image1_path)
    hash2 = calculate_phash(image2_path)

    difference = hash1 - hash2

    return difference