import json

import bpy


bpy.ops.object.select_all(action="SELECT")
bpy.ops.object.delete(use_global=False)
bpy.ops.mesh.primitive_cube_add(size=2, location=(0, 0, 0))
cube = bpy.context.object
cube.name = "OnboardingCube"
for area in bpy.context.screen.areas:
    if area.type == "VIEW_3D":
        area.spaces.active.region_3d.view_distance = 7
        area.spaces.active.region_3d.view_location = cube.location
print(json.dumps({"schema_version": 1, "status": "pass", "object": cube.name,
                  "type": cube.type, "vertices": len(cube.data.vertices),
                  "edges": len(cube.data.edges), "faces": len(cube.data.polygons)}))
