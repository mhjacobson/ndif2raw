# ndif2raw

A program to convert Apple New Disk Image Format (NDIF) images to raw disk 
images.  Apple used to provide this functionality as part of macOS but removed 
it in macOS 11 ("Big Sur").

NDIF images can be recognized by an HFS type ID of `'dimg'`, `'rohd'`, or 
`'hdro'` (as shown by `GetFileInfo` on Mac) and by the presence of an HFS 
resource fork containing a resource of type `'bcem'` (as shown by e.g. `DeRez` 
on Mac).

The code currently knows how to decode a subset of the possible NDIF image 
types and will abort if it sees something it doesn't know how to handle.
