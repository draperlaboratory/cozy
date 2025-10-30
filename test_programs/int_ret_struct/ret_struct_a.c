typedef struct {
    int x;
    int y;
    int z;
} Vector3;

Vector3 crossProduct(Vector3 a, Vector3 b) {
    Vector3 ret = {
        .x = a.y * b.z - a.z * b.y,
        .y = a.z * b.x - a.x * b.z,
        .z = a.x * b.y - a.y * b.x
    };
    return ret;
}